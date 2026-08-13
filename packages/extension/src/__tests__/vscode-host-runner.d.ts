export interface RunExtensionHostSuiteOptions {
	host: "cursor" | "vscode";
	vscodeExecutablePath: string;
	extensionRoot: string;
	extensionTestsPath: string;
	hookRunnerPath: string;
	workspaceFolder: string;
	resultsFile: string;
	home: string;
	extensionId: string;
	managedMarker: string;
	hookMode: "cursor" | "vscode";
	hooksRelativePath: string;
	verbose?: boolean;
	extraLaunchArgs?: string[];
}

export function runExtensionHostSuite(
	opts: RunExtensionHostSuiteOptions,
): Promise<{ runError?: string }>;

export const VSCODE_HOST: {
	extensionId: string;
	managedMarker: string;
	hookMode: "vscode";
	hooksRelativePath: string;
};
