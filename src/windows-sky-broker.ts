import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { z } from "zod";
import {
	BrokerVerificationError,
	DirectBrokerCallError,
	readOfficialPathConfig,
	type DirectBrokerElicitationRequest,
	type DirectBrokerElicitationResponse,
	type DirectBrokerOptions,
	type DirectBrokerResult,
	type OfficialDirectToolSession,
	type RunSync,
} from "./direct-broker.ts";
import type { DirectMethod, DirectToolArguments, JsonObject, JsonValue } from "./tools.ts";
import { isWindowsDirectMethod, type WindowsDirectMethod } from "./windows-tools.ts";

// On Windows the Codex app installs Computer Use as the `@oai/sky` package inside
// its `cua_node` runtime. Its JavaScript client drives the OpenAI-signed
// `codex-computer-use.exe` helper over stdio; there is no MCP mode and no
// app-server in that path, so this broker loads the official client directly.
const SKY_PACKAGE_NAME = "@oai/sky";
const CODEX_RUNTIMES_RELATIVE_PATH = path.join("AppData", "Local", "OpenAI", "Codex", "runtimes", "cua_node");
const SKY_PACKAGE_RELATIVE_PATH = path.join("bin", "node_modules", "@oai", "sky");
export const WINDOWS_HELPER_RELATIVE_PATH = path.join(
	"bin",
	"windows",
	process.arch === "arm64" ? "codex-computer-use-arm64.exe" : "codex-computer-use.exe",
);
const CLIENT_MODULE_RELATIVE_PATH = "dist/project/cua/sky_js/src/targets/windows/internal/computer_use_client.js";
const TRANSPORT_MODULE_RELATIVE_PATH = "dist/project/cua/sky_js/src/targets/windows/internal/helper_transport.js";
// A helper turn shows the official "ChatGPT is using your computer" overlay and
// locks the user's input until the turn ends; element indexes are valid only
// within a turn. Codex ends the turn with the model's turn. Pi closes the session
// when the agent settles; for MCP clients the broker ends an idle turn after this
// long, which must exceed a model's pause between an inspection and its action.
const DEFAULT_TURN_IDLE_MS = 15_000;
const TURN_IDLE_ENV = "CODEX_COMPUTER_USE_TURN_IDLE_MS";

function configuredTurnIdleMs(): number {
	const configured = z.coerce.number().int().positive().safeParse(process.env[TURN_IDLE_ENV]);
	return configured.success ? configured.data : DEFAULT_TURN_IDLE_MS;
}
const OPENAI_SIGNER_ORGANIZATION = "OpenAI OpCo, LLC";
const POWERSHELL_PATH = path.join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe");

const jsonObjectSchema = z.record(z.string(), z.json());
const skyManifestSchema = z.object({ name: z.literal(SKY_PACKAGE_NAME), version: z.string().min(1) });
const clientModuleSchema = z.object({ WindowsComputerUseClient: z.instanceof(Function) });
const transportModuleSchema = z.object({ WindowsHelperTransport: z.instanceof(Function) });
const approvalRequestSchema = z.object({
	message: z.string().optional(),
	meta: jsonObjectSchema.optional(),
}).catchall(z.json());
// Official result shapes from the bundled `docs/api.md`; unknown keys pass through.
const officialWindowSchema = z.object({
	app: z.string(),
	id: z.number(),
	title: z.string().optional(),
}).catchall(z.json());
const officialAppSchema = z.object({
	id: z.string(),
	displayName: z.string().optional(),
	isRunning: z.boolean().optional(),
	windows: z.array(officialWindowSchema).optional(),
}).catchall(z.json());
const officialScreenshotSchema = z.object({
	id: z.string().optional(),
	zIndex: z.number().optional(),
	width: z.number().optional(),
	height: z.number().optional(),
	originX: z.number().optional(),
	originY: z.number().optional(),
	url: z.string().optional(),
}).catchall(z.json());
const officialAccessibilitySchema = z.object({
	tree: z.string().optional(),
	focused_element: z.string().optional(),
	selected_text: z.string().optional(),
	selected_elements: z.array(z.string()).optional(),
	document_text: z.string().optional(),
}).catchall(z.json());
const officialWindowStateSchema = z.object({
	window: officialWindowSchema,
	accessibility: officialAccessibilitySchema.nullable().optional(),
	screenshots: z.array(officialScreenshotSchema).optional(),
}).catchall(z.json());
const dataUrlSchema = z.string().regex(/^data:[^;,]+;base64,[A-Za-z0-9+/=]+$/);

type OfficialWindow = z.infer<typeof officialWindowSchema>;

function productionRunSync(command: string, args: string[]) {
	return spawnSync(command, args, { encoding: "utf8", timeout: 20_000 });
}

function samePath(left: string, right: string): boolean {
	return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
}

/** Authenticode is the Windows counterpart of the macOS codesign Team ID check. */
function verifyAuthenticodeBinary(binaryPath: string, runSync: RunSync): void {
	const literal = binaryPath.replace(/'/g, "''");
	const script = `$signature = Get-AuthenticodeSignature -LiteralPath '${literal}'; [Console]::Out.Write($signature.Status.ToString() + '|' + [string]$signature.SignerCertificate.Subject)`;
	const result = runSync(POWERSHELL_PATH, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script]);
	const output = (result.stdout ?? "").trim();
	const separator = output.indexOf("|");
	if (result.status !== 0 || separator < 0 || output.slice(0, separator) !== "Valid") {
		throw new BrokerVerificationError(`Signature verification failed for ${path.basename(binaryPath)}`);
	}
	const subject = output.slice(separator + 1);
	if (!new RegExp(`(?:^|, )O="${OPENAI_SIGNER_ORGANIZATION}"(?:,|$)`).test(subject)) {
		throw new BrokerVerificationError(`${path.basename(binaryPath)} is not signed by the expected OpenAI organization`);
	}
}

export interface OfficialWindowsClient {
	packagePath: string;
	clientPath: string;
	version: string;
	layout: "installed-runtime" | "configured";
}

interface ResolveOfficialWindowsClientOptions {
	/** Test-only OS-account home override. Production never reads HOME, USERPROFILE or CODEX_HOME. */
	userHome?: string;
	configPath?: string;
	runSync?: RunSync;
}

function readSkyPackageVersion(packagePath: string): string {
	let parsed: unknown;
	try {
		parsed = JSON.parse(readFileSync(path.join(packagePath, "package.json"), "utf8"));
	} catch {
		throw new BrokerVerificationError(`Could not read the ${SKY_PACKAGE_NAME} package manifest at ${packagePath}`);
	}
	const manifest = skyManifestSchema.safeParse(parsed);
	if (!manifest.success) throw new BrokerVerificationError(`${packagePath} is not the official ${SKY_PACKAGE_NAME} package`);
	return manifest.data.version;
}

function checkedCandidate(packagePath: string, layout: OfficialWindowsClient["layout"], runSync: RunSync): OfficialWindowsClient | undefined {
	const clientPath = path.join(packagePath, WINDOWS_HELPER_RELATIVE_PATH);
	if (!existsSync(clientPath)) return undefined;
	let canonicalPackage: string;
	let canonicalClient: string;
	try {
		canonicalPackage = realpathSync(packagePath);
		canonicalClient = realpathSync(clientPath);
	} catch {
		throw new BrokerVerificationError("Could not resolve the official Windows Computer Use helper path");
	}
	if (
		!samePath(canonicalPackage, path.resolve(packagePath))
		|| !samePath(canonicalClient, path.resolve(clientPath))
		|| !samePath(canonicalClient.slice(0, canonicalPackage.length + 1), `${canonicalPackage}${path.sep}`)
	) {
		throw new BrokerVerificationError("Official Windows Computer Use helper path was not canonical");
	}
	const version = readSkyPackageVersion(canonicalPackage);
	verifyAuthenticodeBinary(canonicalClient, runSync);
	return { packagePath: canonicalPackage, clientPath: canonicalClient, version, layout };
}

/** Newest first: the Codex app keeps one runtime directory per installed version. */
function installedRuntimeCandidates(runtimesRoot: string): string[] {
	if (!existsSync(runtimesRoot)) return [];
	const candidates: Array<{ packagePath: string; modified: number }> = [];
	for (const entry of readdirSync(runtimesRoot, { withFileTypes: true })) {
		if (!entry.isDirectory()) continue;
		const packagePath = path.join(runtimesRoot, entry.name, SKY_PACKAGE_RELATIVE_PATH);
		try {
			candidates.push({ packagePath, modified: statSync(path.join(packagePath, WINDOWS_HELPER_RELATIVE_PATH)).mtimeMs });
		} catch {
			// A runtime without the helper is not a Computer Use runtime.
		}
	}
	return candidates.sort((left, right) => right.modified - left.modified).map((candidate) => candidate.packagePath);
}

/** Resolve the configured `@oai/sky` package, or else the newest one installed by the Codex app. */
export function resolveOfficialWindowsClient(options: ResolveOfficialWindowsClientOptions = {}): OfficialWindowsClient {
	const runSync = options.runSync ?? productionRunSync;
	const config = options.configPath ? readOfficialPathConfig(options.configPath) : {};
	const where = options.configPath ? `in ${options.configPath}` : "in the Computer Use config.json in the state directory";
	const hint = `Find the ${SKY_PACKAGE_NAME} package installed by the Codex app under AppData\\Local\\OpenAI\\Codex\\runtimes\\cua_node. Then set "computerUseAppPath" to its absolute path ${where}.`;
	if (config.computerUseAppPath) {
		const configuredPackage = existsSync(config.computerUseAppPath) ? realpathSync(config.computerUseAppPath) : path.resolve(config.computerUseAppPath);
		const configured = checkedCandidate(configuredPackage, "configured", runSync);
		if (configured) return configured;
		throw new BrokerVerificationError(
			`Official Windows Computer Use helper was not found. Checked: ${path.join(configuredPackage, WINDOWS_HELPER_RELATIVE_PATH)}. ${hint}`,
		);
	}
	const userHome = options.userHome ?? os.userInfo().homedir;
	const runtimesRoot = path.join(existsSync(userHome) ? realpathSync(userHome) : path.resolve(userHome), CODEX_RUNTIMES_RELATIVE_PATH);
	const checked: string[] = [];
	for (const packagePath of installedRuntimeCandidates(runtimesRoot)) {
		const installed = checkedCandidate(packagePath, "installed-runtime", runSync);
		if (installed) return installed;
		checked.push(path.join(packagePath, WINDOWS_HELPER_RELATIVE_PATH));
	}
	throw new BrokerVerificationError(
		`Official Windows Computer Use helper was not found. Checked: ${checked.length > 0 ? checked.join(", ") : runtimesRoot}. ${hint}`,
	);
}

export function verifyOfficialWindowsBroker(options: ResolveOfficialWindowsClientOptions = {}) {
	const client = resolveOfficialWindowsClient(options);
	const clientBuild = createHash("sha256").update(readFileSync(client.clientPath)).digest("hex").slice(0, 16);
	return { brokerVersion: `${SKY_PACKAGE_NAME} ${client.version}`, clientBuild, client };
}

/** The official `WindowsComputerUseClient` surface this broker uses; results are the official JSON values. */
export type WindowsSkyClient = { close(): Promise<void> }
	& Record<WindowsDirectMethod, (input: DirectToolArguments) => Promise<JsonValue>>;

/** The official helper transport surface this broker uses. */
export interface WindowsSkyTransport {
	request(method: string, params: JsonObject, options?: { codexTurnMetadata?: JsonObject }): Promise<JsonValue>;
	close(): Promise<void>;
}

/** The official client plus the turn control that only its transport exposes. */
export interface WindowsSkyRuntime {
	client: WindowsSkyClient;
	endTurn(turnMeta: JsonObject): Promise<void>;
}

type WindowsSkyTransportConstructor = new (options: { helperCommand: string; helperArgs: string[]; timeoutMs?: number }) => WindowsSkyTransport;
type WindowsSkyClientConstructor = new (options: { transport: WindowsSkyTransport }) => WindowsSkyClient;

export interface WindowsBrokerOptions extends Pick<DirectBrokerOptions, "timeoutMs" | "signal" | "onElicitation" | "supportsOpenAiFormElicitation" | "configPath"> {
	/** Test-only signature bypass. */
	skipSignatureVerification?: boolean;
	/** Test-only runtime factory, used only with skipSignatureVerification. */
	loadRuntime?: () => Promise<WindowsSkyRuntime>;
	/** Test-only idle period before the helper turn ends. */
	turnIdleMs?: number;
}

async function loadOfficialRuntime(client: OfficialWindowsClient): Promise<WindowsSkyRuntime> {
	const moduleUrl = (relativePath: string) => pathToFileURL(path.join(client.packagePath, relativePath)).href;
	const transportModule = transportModuleSchema.safeParse(await import(moduleUrl(TRANSPORT_MODULE_RELATIVE_PATH)));
	const clientModule = clientModuleSchema.safeParse(await import(moduleUrl(CLIENT_MODULE_RELATIVE_PATH)));
	if (!transportModule.success || !clientModule.success) {
		throw new BrokerVerificationError(`The official ${SKY_PACKAGE_NAME} package does not export the Windows Computer Use client`);
	}
	// SAFETY: the verified official module exports its helper transport class, checked above to be a constructor function.
	const WindowsHelperTransport = transportModule.data.WindowsHelperTransport as WindowsSkyTransportConstructor;
	// SAFETY: the verified official module exports its client class, checked above to be a constructor function.
	const WindowsComputerUseClient = clientModule.data.WindowsComputerUseClient as WindowsSkyClientConstructor;
	// Owning the transport is what allows end_turn. The client adds --parent-pid
	// only to a helper it starts itself, so pass it here: the helper exits with this process.
	const transport = new WindowsHelperTransport({
		helperCommand: client.clientPath,
		helperArgs: ["--parent-pid", String(process.pid)],
		timeoutMs: 60_000,
	});
	return {
		client: new WindowsComputerUseClient({ transport }),
		async endTurn(turnMeta) {
			await transport.request("end_turn", {}, { codexTurnMetadata: turnMeta });
		},
	};
}

// The official client reads app-approval and turn metadata from Codex's node_repl
// host object. Outside node_repl this process provides that minimal host surface,
// forwarding each approval to the caller as an elicitation.
interface NodeReplHostShim {
	config: Record<string, never>;
	requestMeta: JsonObject;
	createElicitation(request: JsonValue): Promise<DirectBrokerElicitationResponse>;
}
type ApprovalHandler = (request: JsonValue) => Promise<DirectBrokerElicitationResponse>;
let activeApproval: ApprovalHandler | undefined;
const nodeReplHostShim: NodeReplHostShim = {
	config: {},
	requestMeta: {},
	createElicitation(request) {
		return activeApproval ? activeApproval(request) : Promise.resolve({ action: "cancel" });
	},
};

function installNodeReplHostShim(): void {
	// SAFETY: globalThis carries the node_repl host slot the official client reads; this process owns it while unset.
	const host = globalThis as { nodeRepl?: NodeReplHostShim };
	if (host.nodeRepl === undefined) host.nodeRepl = nodeReplHostShim;
	else if (host.nodeRepl !== nodeReplHostShim) {
		throw new BrokerVerificationError("Another node_repl host already owns the official Windows Computer Use client in this process");
	}
}

// Codex's node_repl host remembers session approvals and marks later requests for
// that app as approved; without the mark the helper asks on every request. This
// process keeps the same memory for its lifetime, which is the Pi or MCP session.
const APPROVED_APP_META_KEY = "x-oai-cua-approved-app";
const sessionApprovedApps = new Set<string>();
const approvalAppSchema = z.object({ meta: z.object({ tool_params: z.object({ app: z.string().min(1) }) }) });
const callTargetSchema = z.union([
	z.object({ window: z.object({ app: z.string().min(1) }) }).transform((value) => value.window.app),
	z.object({ app: z.string().min(1) }).transform((value) => value.app),
]);

function approvedRequestMeta(turnMeta: JsonObject, args: DirectToolArguments): JsonObject {
	const target = callTargetSchema.safeParse(args);
	return target.success && sessionApprovedApps.has(target.data) ? { ...turnMeta, [APPROVED_APP_META_KEY]: target.data } : turnMeta;
}

export function approvalElicitation(request: JsonValue): DirectBrokerElicitationRequest {
	const parsed = approvalRequestSchema.safeParse(request);
	const meta = parsed.success ? parsed.data.meta ?? {} : {};
	const persist = z.array(z.string().min(1)).safeParse(meta.persist);
	const options = persist.success && persist.data.length > 0 ? persist.data : ["session"];
	return {
		mode: "form",
		message: parsed.success && parsed.data.message ? parsed.data.message : "Allow Computer Use to use this app?",
		requestedSchema: {
			type: "object",
			properties: { persist: { type: "string", enum: options, description: "How long the approval lasts" } },
			required: ["persist"],
		},
		elicitationId: randomUUID(),
		_meta: meta,
	};
}

/** Drops undefined members so the official value is plain JSON. */
function officialJson(value: JsonValue | undefined): JsonValue {
	return value === undefined ? null : JSON.parse(JSON.stringify(value));
}

function imageBlock(url: string | undefined): JsonObject | null {
	const dataUrl = dataUrlSchema.safeParse(url);
	if (!dataUrl.success) return null;
	const [header, data] = dataUrl.data.split(",", 2);
	return { type: "image", data, mimeType: header.slice("data:".length, -";base64".length) };
}

function windowLine(window: OfficialWindow): string {
	return `${window.id} — ${window.app}${window.title === undefined ? "" : ` — ${JSON.stringify(window.title)}`}`;
}

/** Official JavaScript results become MCP content blocks; the structured result is the official value. */
export function windowsResultContent(method: WindowsDirectMethod, result: JsonValue | undefined): Pick<DirectBrokerResult, "content" | "structuredContent"> {
	const value = officialJson(result);
	switch (method) {
		case "list_apps": {
			const apps = z.array(officialAppSchema).safeParse(value);
			if (!apps.success) break;
			const lines = apps.data.map((app) => {
				const summary = `${app.displayName === undefined ? "" : `${app.displayName} — `}${app.id}${app.isRunning === true ? " [running]" : ""}`;
				const windows = app.windows ?? [];
				return windows.length > 0 ? `${summary} — windows: ${windows.map(windowLine).join("; ")}` : summary;
			});
			return { content: [{ type: "text", text: lines.join("\n") }], structuredContent: { apps: apps.data } };
		}
		case "list_windows": {
			const windows = z.array(officialWindowSchema).safeParse(value);
			if (!windows.success) break;
			return { content: [{ type: "text", text: windows.data.map(windowLine).join("\n") }], structuredContent: { windows: windows.data } };
		}
		case "get_window": {
			const window = officialWindowSchema.safeParse(value);
			if (!window.success) break;
			return { content: [{ type: "text", text: windowLine(window.data) }], structuredContent: { window: window.data } };
		}
		case "get_window_state": {
			const state = officialWindowStateSchema.safeParse(value);
			if (!state.success) break;
			const accessibility = state.data.accessibility ?? null;
			const lines = [`window: ${windowLine(state.data.window)}`];
			const images: JsonObject[] = [];
			const screenshots: JsonObject[] = [];
			for (const screenshot of state.data.screenshots ?? []) {
				const { url, ...metadata } = screenshot;
				const image = imageBlock(url);
				if (image) images.push(image);
				screenshots.push({ ...metadata, image });
				const size = metadata.width === undefined || metadata.height === undefined ? "" : ` ${metadata.width}x${metadata.height}`;
				const origin = metadata.originX === undefined || metadata.originY === undefined ? "" : ` at (${metadata.originX}, ${metadata.originY})`;
				lines.push(`screenshot ${metadata.id ?? ""}:${size}${origin} z=${metadata.zIndex ?? 0}`);
			}
			if (accessibility) {
				for (const key of ["focused_element", "selected_text", "document_text"] as const) {
					const text = accessibility[key];
					if (text !== undefined) lines.push(`${key}: ${text}`);
				}
				if (accessibility.selected_elements && accessibility.selected_elements.length > 0) {
					lines.push(`selected_elements:\n${accessibility.selected_elements.join("\n")}`);
				}
				if (accessibility.tree !== undefined) lines.push(`accessibility tree:\n${accessibility.tree}`);
			}
			return {
				content: [{ type: "text", text: lines.join("\n") }, ...images],
				structuredContent: { window: state.data.window, accessibility, screenshots },
			};
		}
		default:
			return { content: [{ type: "text", text: "ok" }] };
	}
	// An unrecognised official result still reaches the caller unchanged.
	return { content: [{ type: "text", text: JSON.stringify(value) }], structuredContent: value };
}

const transportFailurePattern = /helper exited|helper .*timed out|client is closed|native pipe|transport/i;

export async function createOfficialWindowsToolSession(options: WindowsBrokerOptions = {}): Promise<OfficialDirectToolSession> {
	const verification = options.skipSignatureVerification
		? { brokerVersion: "test-sky", clientBuild: "test-helper", client: undefined }
		: verifyOfficialWindowsBroker({ configPath: options.configPath });
	const evidence = { brokerVersion: verification.brokerVersion, clientBuild: verification.clientBuild };
	let runtime: WindowsSkyRuntime;
	const sessionId = randomUUID();
	let turnMeta: JsonObject = { session_id: sessionId, turn_id: randomUUID() };
	try {
		installNodeReplHostShim();
		nodeReplHostShim.requestMeta = turnMeta;
		if (options.loadRuntime) runtime = await options.loadRuntime();
		else if (verification.client) runtime = await loadOfficialRuntime(verification.client);
		else throw new BrokerVerificationError("The official Windows Computer Use client was not verified");
	} catch (error) {
		const primary = error instanceof Error ? error : new Error(String(error));
		throw new DirectBrokerCallError(primary.message, true, primary, evidence);
	}
	const client = runtime.client;

	let fatalError: Error | undefined;
	let closed = false;
	let closePromise: Promise<void> | undefined;
	let callActive = false;
	let turnActive = false;
	let turnTimer: NodeJS.Timeout | undefined;
	let turnEnding: Promise<void> | undefined;

	const clearTurnTimer = (): void => {
		if (turnTimer) clearTimeout(turnTimer);
		turnTimer = undefined;
	};
	// Ends the current helper turn, which removes the official overlay and gives the
	// user their input back. The next call starts a new turn under a new turn id.
	const endTurn = (): Promise<void> => {
		clearTurnTimer();
		if (!turnActive) return turnEnding ?? Promise.resolve();
		turnActive = false;
		const ended = turnMeta;
		turnMeta = { session_id: sessionId, turn_id: randomUUID() };
		turnEnding = runtime.endTurn(ended).catch(() => undefined).finally(() => { turnEnding = undefined; });
		return turnEnding;
	};
	const scheduleTurnEnd = (): void => {
		clearTurnTimer();
		turnTimer = setTimeout(() => { void endTurn(); }, options.turnIdleMs ?? configuredTurnIdleMs());
		turnTimer.unref();
	};

	const close = (): Promise<void> => {
		closePromise ??= (async () => {
			closed = true;
			activeApproval = undefined;
			clearTurnTimer();
			if (turnEnding) await turnEnding;
			try {
				await new Promise<void>((resolve, reject) => {
					const timer = setTimeout(() => reject(new Error("Official Windows Computer Use helper did not close")), 5_000);
					client.close().then(() => { clearTimeout(timer); resolve(); }, (error) => { clearTimeout(timer); reject(error); });
				});
			} catch (error) {
				throw new Error("Official direct Computer Use broker cleanup failed", { cause: error });
			}
			if (fatalError) throw fatalError;
		})();
		return closePromise;
	};
	const cancel = (error: Error): void => {
		fatalError ??= error;
		void close().catch(() => undefined);
	};
	const guard = (method: string, operation: Promise<JsonValue>, timeoutMs: number, signal?: AbortSignal): Promise<JsonValue> =>
		new Promise<JsonValue>((resolve, reject) => {
			let settled = false;
			const finish = (callback: () => void): void => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				signal?.removeEventListener("abort", abort);
				callback();
			};
			const abort = (): void => finish(() => {
				const error = new Error("Direct Computer Use request cancelled");
				cancel(error);
				reject(error);
			});
			const timer = setTimeout(() => finish(() => {
				const error = new Error(`Official Windows Computer Use request timed out: ${method}`);
				cancel(error);
				reject(error);
			}), timeoutMs);
			if (signal?.aborted) { abort(); return; }
			signal?.addEventListener("abort", abort, { once: true });
			operation.then((value) => finish(() => resolve(value)), (error) => finish(() => reject(error)));
		});

	return {
		async call(method: DirectMethod, args: DirectToolArguments, callOptions = {}) {
			if (closed) throw new DirectBrokerCallError("Official Windows Computer Use session is closed", true, undefined, evidence);
			if (callActive) throw new DirectBrokerCallError("Official Windows Computer Use session does not allow concurrent calls", false, undefined, evidence);
			if (!isWindowsDirectMethod(method) || !(method in client)) {
				throw new DirectBrokerCallError(`The official Windows Computer Use client does not provide ${method}`, true, undefined, evidence);
			}
			callActive = true;
			clearTurnTimer();
			if (turnEnding) await turnEnding;
			turnActive = true;
			let elicitationRequests = 0;
			nodeReplHostShim.requestMeta = approvedRequestMeta(turnMeta, args);
			activeApproval = async (request) => {
				elicitationRequests += 1;
				let response: DirectBrokerElicitationResponse = { action: "cancel" };
				if (callOptions.onElicitation) {
					try { response = await callOptions.onElicitation(approvalElicitation(request)); }
					catch { response = { action: "cancel" }; }
				}
				const approved = approvalAppSchema.safeParse(request);
				if (response.action === "accept" && approved.success) {
					sessionApprovedApps.add(approved.data.meta.tool_params.app);
					const target = callTargetSchema.safeParse(args);
					if (target.success) sessionApprovedApps.add(target.data);
				}
				return response;
			};
			const callEvidence = () => ({ ...evidence, elicitationRequests, modelTurnsStarted: 0 as const, ephemeralThread: true as const });
			try {
				if (fatalError) throw fatalError;
				const result = await guard(method, Promise.resolve(client[method](args)), callOptions.timeoutMs ?? 120_000, callOptions.signal);
				return { ...windowsResultContent(method, result), isError: false, ...callEvidence(), brokerCleanupVerified: false };
			} catch (error) {
				const failure = error instanceof Error ? error : new Error(String(error));
				if (fatalError || transportFailurePattern.test(failure.message)) {
					fatalError ??= failure;
					throw new DirectBrokerCallError(failure.message, false, failure, { directCalls: 1, ...callEvidence() });
				}
				// The helper rejected the request: that is the official error text for this call.
				return { content: [{ type: "text", text: failure.message }], isError: true, ...callEvidence(), brokerCleanupVerified: false };
			} finally {
				activeApproval = undefined;
				callActive = false;
				if (!closed && !fatalError) scheduleTurnEnd();
			}
		},
		close,
	};
}

export async function callOfficialWindowsTool(
	method: DirectMethod,
	args: DirectToolArguments,
	options: WindowsBrokerOptions = {},
): Promise<DirectBrokerResult> {
	let session: OfficialDirectToolSession | undefined;
	let result: DirectBrokerResult | undefined;
	let failure: unknown;
	try {
		session = await createOfficialWindowsToolSession(options);
		result = await session.call(method, args, options);
	} catch (error) {
		failure = error;
	}
	let cleanupVerified = failure instanceof DirectBrokerCallError ? failure.cleanupVerified : false;
	try {
		if (session) {
			await session.close();
			cleanupVerified = true;
		}
	} catch (cleanupError) {
		const closeFailure = cleanupError instanceof Error ? cleanupError : new Error(String(cleanupError));
		if (closeFailure.message !== "Official direct Computer Use broker cleanup failed") {
			throw new DirectBrokerCallError(closeFailure.message, true, closeFailure, failure instanceof DirectBrokerCallError ? failure : {});
		}
		throw new DirectBrokerCallError(closeFailure.message, false, closeFailure, failure instanceof DirectBrokerCallError ? failure : {});
	}
	if (failure) {
		if (failure instanceof DirectBrokerCallError) {
			throw new DirectBrokerCallError(failure.message, cleanupVerified, failure, failure);
		}
		throw failure;
	}
	if (!result) throw new DirectBrokerCallError("Official direct Computer Use ended without a result", cleanupVerified);
	return { ...result, brokerCleanupVerified: true };
}
