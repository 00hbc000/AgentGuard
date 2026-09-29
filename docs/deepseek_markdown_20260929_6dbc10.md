# **All Possible Input Types**

### **NVIDIA SkillSpector**

| **Input Type** | **Supported?** | **Details** |
| --- | --- | --- |
| **Local files** | Yes | `.md` file, `.zip` file, directory |
| **SKILL.md** | Yes | Direct file path |
| **Markdown files** | Yes | `.md` file directly |
| **Python files** | Yes (as part of directory) | Scanned within directory |
| **JavaScript files** | Yes (as part of directory) | Scanned within directory |
| **Configuration files** | Yes (as part of directory) | Scanned within directory |
| **Local directories** | Yes | Single skill directory, parent directory |
| **Single skill directory** | Yes | Directory with SKILL.md |
| **Parent directory with multiple skills** | Yes | Scans the directory |
| **Recursive directories** | Yes | Discovery is recursive |
| **Nested skills** | Yes | Discovered recursively |
| **Empty directory** | Yes | Produces empty findings |
| **Directory without SKILL.md** | Yes (may produce no findings) | SkillSpector may still scan files |
| **Directory with multiple SKILL.md** | NOT VERIFIED | — |
| **ZIP** | Yes | Supported |
| **TAR** | NOT VERIFIED | — |
| **Other archives** | NOT VERIFIED | — |
| **GitHub repository** | Yes | Git URL supported |
| **GitLab** | Yes (generic Git URL) | Generic Git URL |
| **Generic Git URL** | Yes | Supported |
| **HTTPS Git URL** | Yes | Supported |
| **SSH Git URL** | NOT VERIFIED | — |
| **Branch** | NOT VERIFIED | — |
| **Tag** | NOT VERIFIED | — |
| **Commit** | NOT VERIFIED | — |
| **Subdirectory** | NOT VERIFIED | — |
| **Private repositories** | NOT VERIFIED | — |
| **URLs** | Yes | Git URL, file URL, `.zip` URL |
| **GitHub URLs** | Yes | Supported |
| **Raw URLs** | Yes | File URL |
| **File URLs** | Yes | `file://` |
| **ZIP URLs** | Yes | `.zip` URL |
| **Other HTTP/HTTPS URLs** | Yes | For zip/Git |
| **Multiple inputs** | NOT VERIFIED for CLI | — |
| **Batch input** | NOT VERIFIED | — |

### **Cisco AI Defense Skill Scanner**

| **Input Type** | **Supported?** | **Details** |
| --- | --- | --- |
| **Local files** | Yes | Via `--skill-file` |
| **SKILL.md** | Yes | Default metadata file |
| **Markdown files** | Yes | `.md` files in directory |
| **Python files** | Yes | Analyzed as part of skill |
| **JavaScript files** | Yes | Analyzed as part of skill |
| **Configuration files** | Yes | Analyzed as part of skill |
| **Local directories** | Yes | Single skill directory |
| **Single skill directory** | Yes | `scan /path/to/skill` |
| **Parent directory with multiple skills** | Yes | `scan-all /path/to/skills` |
| **Recursive directories** | Yes | `--recursive` (default: True) |
| **Nested skills** | Yes | Discovered recursively |
| **Empty directory** | Yes | — |
| **Directory without SKILL.md** | Yes | `--lenient` mode |
| **Directory with multiple SKILL.md** | NOT VERIFIED | — |
| **ZIP** | Yes | Via `ContentExtractor` |
| **TAR** | Yes | Via `ContentExtractor` |
| **Other archives** | NOT VERIFIED | — |
| **GitHub repository** | Yes | `scan-repo` command |
| **GitLab** | NOT VERIFIED | — |
| **Generic Git URL** | NOT VERIFIED | — |
| **HTTPS Git URL** | Yes | GitHub repo URL |
| **SSH Git URL** | NOT VERIFIED | — |
| **Branch** | NOT VERIFIED | — |
| **Tag** | NOT VERIFIED | — |
| **Commit** | NOT VERIFIED | — |
| **Subdirectory** | NOT VERIFIED | — |
| **Private repositories** | NOT VERIFIED | — |
| **URLs** | Yes | GitHub repo URL |
| **GitHub URLs** | Yes | `scan-repo` |
| **Raw URLs** | NOT VERIFIED | — |
| **File URLs** | NOT VERIFIED | — |
| **ZIP URLs** | NOT VERIFIED | — |
| **Other HTTP/HTTPS URLs** | NOT VERIFIED | — |
| **Multiple inputs** | Yes | `scan-all` |
| **Batch input** | Yes | `scan-all` |

---

# **Input Requirements**

### **NVIDIA SkillSpector**

**SKILL.md:**

- Mandatory? Yes for skill discovery, but `.md` files can be passed directly
- Filename case sensitivity: NOT VERIFIED
- Required metadata: YAML frontmatter with `name`, `description`
- Frontmatter bytes ceiling: 256 KiB; YAML nodes: 10,000; YAML nesting depth: 64; Manifest parse time: 1 second

**Directory:**

- Required structure: SKILL.md at root
- Required files: SKILL.md
- Optional files: Any
- Supported subdirectories: All except ignored
- Ignored directories: `.git` internals
- Traversal depth: 64
- Discovered entries: 10,000
- Canonical cached source bytes: 64 MiB

**Repository:**

- Required branch: NOT VERIFIED
- Default branch: NOT VERIFIED
- Authentication: NOT VERIFIED
- Network access: Required for Git URLs
- Repository size limits: Bundle ceilings apply

### **Cisco AI Defense Skill Scanner**

**SKILL.md:**

- Mandatory? Yes, unless `-lenient` or `-skill-file` is used
- Filename case sensitivity: NOT VERIFIED
- Required metadata: YAML frontmatter with `name`, `description`
- Allowed fields: `name`, `description`, `metadata`
- Unknown fields: NOT VERIFIED
- Maximum length: NOT VERIFIED

**Directory:**

- Required structure: Skill directory with SKILL.md
- Required files: SKILL.md (default)
- Optional files: Any
- Supported subdirectories: All except `.git`
- Ignored directories: `.git` internals
- Recursive: Yes (default: True)
- Lenient mode: Fall back to `.md` files when SKILL.md absent

**Repository:**

- Required branch: NOT VERIFIED
- Default branch: NOT VERIFIED
- Authentication: Public repos only via `scan-repo`
- Network access: Required
- Repository size limits: NOT VERIFIED

---

# **Input Validation**

### **NVIDIA SkillSpector**

| **INPUT** | **VALIDATION** | **RESULT** | **ERROR / CONTINUE** |
| --- | --- | --- | --- |
| Local path | Existence check | If exists, continue | Error if missing |
| Directory | Existence, SKILL.md | If valid, continue | Error if invalid |
| ZIP file | Existence, format | If valid, extract | Error if invalid |
| Git URL | URL format | If valid, clone | Error if invalid |
| `file://` URL | Rejected over HTTP | Security measure | Error |
| Empty input | Validation | Error | Error |
| Oversized input | Bundle ceilings | Partial analysis | Continue with limitation |
| Recursive depth | 64 | Ceiling reached | Continue with limitation |

**Ingest caps:** A breach of either ingest cap fails closed with `IngestLimitExceededError`.

### **Cisco AI Defense Skill Scanner**

| **INPUT** | **VALIDATION** | **RESULT** | **ERROR / CONTINUE** |
| --- | --- | --- | --- |
| Local path | Existence check | If exists, continue | Error if missing |
| Directory | SKILL.md presence | If valid, continue | Error if missing |
| ZIP/TAR | Archive format | Extract with protections | Error if malicious |
| Git URL | GitHub URL format | Clone | Error if invalid |
| Empty directory | Allowed | Continue | No error |
| Oversized input | Size limits | Ceiling reached | Continue with limitation |
| Malformed SKILL.md | YAML parse | Error unless `--lenient` | Error or continue |

**Validation errors:** Cisco classifies skill loading failures as validation failures and includes the loader's actionable message, while preserving generic internal-failure handling for unexpected runtime faults. The validation message helps the skill author fix missing or malformed metadata but must not expose stack traces. Custom exceptions include `SkillValidationError` (raised when skill validation fails — invalid skill manifest, missing required fields, invalid skill structure) and `SkillLoadError` (raised when unable to load a skill package — missing SKILL.md file).

# **All CLI Inputs**

### **NVIDIA SkillSpector**

| **OPTION** | **TYPE** | **DEFAULT** | **REQUIRED?** | **INPUT VALUE** | **DESCRIPTION** | **EFFECT** | **EXAMPLE** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `scan` | command | — | Yes | Path/URL | Scan a skill | Runs scan | `skillspector scan ./my-skill/` |
| `--format` / `-f` | choice | terminal | No | terminal, json, markdown, sarif | Output format | Changes output | `--format json` |
| `--output` / `-o` | path | — | No | File path | Output file | Writes to file | `--output report.json` |
| `--no-llm` | flag | False | No | — | Skip LLM analysis | Static only | `--no-llm` |
| `--fail-on-findings` | flag | False | No | — | Gate on any active finding | Exit 1 if findings | `--fail-on-findings` |
| `--fail-on-incomplete` | flag | False | No | — | Gate on incomplete coverage | Exit 1 if incomplete | `--fail-on-incomplete` |
| `--baseline` | path | — | No | File path | Suppress findings | Filters findings | `--baseline .skillspector-baseline.yaml` |
| `--show-suppressed` | flag | False | No | — | Show suppressed | Lists suppressed | `--show-suppressed` |
| `mcp` | command | — | No | — | MCP server | Runs MCP | `skillspector mcp` |

**Exit codes:**

- `0`: Scan completed, `risk_score` ≤ 50 (recommendation `SAFE` or `CAUTION`)
- `1`: Scan completed and either `risk_score` > 50, `-fail-on-findings` found an active finding, or `-fail-on-incomplete` found partial/incomplete analysis
- `2`: Missing, malformed, or unsupported baseline file

### **Cisco AI Defense Skill Scanner**

| **OPTION** | **TYPE** | **DEFAULT** | **REQUIRED?** | **INPUT VALUE** | **DESCRIPTION** | **EFFECT** | **EXAMPLE** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `scan` | command | — | Yes | Path | Scan single skill | Runs scan | `skill-scanner scan /path` |
| `scan-all` | command | — | No | Path | Scan multiple skills | Batch scan | `skill-scanner scan-all /path` |
| `scan-repo` | command | — | No | Repo URL | Scan GitHub repo | Clones and scans | `skill-scanner scan-repo owner/repo` |
| `--format` | choice | summary | No | summary, json, markdown, table, sarif, html | Output format | Changes output | `--format json` |
| `--output` / `-o` | path | — | No | File path | Default output file | Writes to file | `--output report.json` |
| `--output-json` | path | — | No | File path | JSON output path | Writes JSON | `--output-json report.json` |
| `--output-sarif` | path | — | No | File path | SARIF output path | Writes SARIF | `--output-sarif report.sarif` |
| `--output-markdown` | path | — | No | File path | Markdown output path | Writes Markdown | `--output-markdown report.md` |
| `--output-html` | path | — | No | File path | HTML output path | Writes HTML | `--output-html report.html` |
| `--output-table` | path | — | No | File path | Table output path | Writes table | `--output-table report.txt` |
| `--recursive` / `-r` | flag | True | No | — | Recursive scan | Search recursively | `--recursive` |
| `--no-recursive` | flag | — | No | — | Disable recursive | Single directory | `--no-recursive` |
| `--check-overlap` | flag | False | No | — | Cross-skill check | Overlap detection | `--check-overlap` |
| `--use-behavioral` | flag | False | No | — | Enable behavioral | AST dataflow | `--use-behavioral` |
| `--use-llm` | flag | False | No | — | Enable LLM | Semantic analysis | `--use-llm` |
| `--use-virustotal` | flag | False | No | — | Enable VirusTotal | Binary scanning | `--use-virustotal` |
| `--vt-api-key` | string | — | No | API key | VT API key | Authenticates | `--vt-api-key KEY` |
| `--vt-upload-files` | flag | False | No | — | Upload to VT | Uploads files | `--vt-upload-files` |
| `--use-aidefense` | flag | False | No | — | Enable AI Defense | Cloud analysis | `--use-aidefense` |
| `--aidefense-api-key` | string | — | No | API key | AI Defense key | Authenticates | `--aidefense-api-key KEY` |
| `--aidefense-api-url` | string | — | No | URL | AI Defense URL | Endpoint | `--aidefense-api-url URL` |
| `--use-osv` | flag | False | No | — | Enable OSV | CVE lookup | `--use-osv` |
| `--llm-provider` | choice | — | No | anthropic, openai, openai-compatible | LLM provider | Provider selection | `--llm-provider anthropic` |
| `--llm-consensus-runs` | number | — | No | N | Consensus runs | Multiple LLM runs | `--llm-consensus-runs 3` |
| `--llm-max-tokens` | number | — | No | N | Max tokens | Token limit | `--llm-max-tokens 4096` |
| `--llm-reasoning-effort` | choice | — | No | Level | Reasoning effort | Effort level | `--llm-reasoning-effort high` |
| `--use-trigger` | flag | False | No | — | Enable trigger | Trigger analysis | `--use-trigger` |
| `--enable-meta` | flag | False | No | — | Enable meta | False positive filter | `--enable-meta` |
| `--adjudicate` | flag | False | No | — | Enable adjudicate | LLM review | `--adjudicate` |
| `--policy` | string | balanced | No | Preset or path | Scan policy | Policy enforcement | `--policy strict` |
| `--lenient` | flag | False | No | — | Lenient mode | Tolerate malformed | `--lenient` |
| `--skill-file` | string | SKILL.md | No | Filename | Custom metadata | Use custom file | `--skill-file SKILL.md` |
| `--custom-rules` | path | — | No | Directory | Custom YARA rules | Use custom rules | `--custom-rules ./rules` |
| `--rule-packs` | list | — | No | Pack names | Rule packs | Enable packs | `--rule-packs atr` |
| `--trusted-rule-pack` | path | — | No | Path | Trusted pack | Load trusted pack | `--trusted-rule-pack ./pack` |
| `--cel-mode` | choice | off | No | off, shadow, enforce | CEL mode | Override CEL | `--cel-mode enforce` |
| `--taxonomy` | path | — | No | Path | Taxonomy override | Override taxonomy | `--taxonomy ./taxonomy.json` |
| `--threat-mapping` | path | — | No | Path | Threat mapping | Override mapping | `--threat-mapping ./mapping.json` |
| `--fail-on-findings` | flag | False | No | — | Exit on findings | Exit 1 on CRITICAL/HIGH | `--fail-on-findings` |
| `--fail-on-severity` | choice | — | No | critical, high, medium, low, info | Exit threshold | Fail on severity | `--fail-on-severity high` |
| `--detailed` | flag | False | No | — | Detailed output | Full details | `--detailed` |
| `--verbose` | flag | False | No | — | Verbose output | More info | `--verbose` |
| `--compact` | flag | False | No | — | Compact JSON | Compact output | `--compact` |
| `--render-markdown` | flag | — | No | — | Render markdown | Render in terminal | `--render-markdown` |
| `--no-render-markdown` | flag | — | No | — | Raw markdown | Print raw | `--no-render-markdown` |

**Exit codes:** The `scan` and `scan-all` commands return a non-zero exit code when findings meet or exceed a configurable severity threshold. `--fail-on-severity` takes precedence over `--fail-on-findings`.

# **All Output Types**

### **NVIDIA SkillSpector**

| **FORMAT** | **HOW TO ENABLE** | **FILE EXTENSION** | **MACHINE READABLE?** | **COMPLETE?** | **RECOMMENDED FOR ORCHESTRATOR?** |
| --- | --- | --- | --- | --- | --- |
| Terminal | Default | — | No | Yes | No |
| JSON | `--format json` | `.json` | Yes | Yes | **Yes** |
| Markdown | `--format markdown` | `.md` | No | Yes | No |
| SARIF | `--format sarif` | `.sarif` | Yes | Yes | **Yes** |

### **Cisco AI Defense Skill Scanner**

| **FORMAT** | **HOW TO ENABLE** | **FILE EXTENSION** | **MACHINE READABLE?** | **COMPLETE?** | **RECOMMENDED FOR ORCHESTRATOR?** |
| --- | --- | --- | --- | --- | --- |
| Summary | Default | — | No | Yes | No |
| JSON | `--format json` | `.json` | Yes | Yes | **Yes** |
| Markdown | `--format markdown` | `.md` | No | Yes | No |
| Table | `--format table` | — | No | Yes | No |
| SARIF | `--format sarif` | `.sarif` | Yes | Yes | **Yes** |
| HTML | `--format html` | `.html` | No | Yes | No |

**Cisco:** May specify multiple `--format` flags to produce several reports in one run.

---

---

## **Side-by-Side Input Comparison**

| **INPUT TYPE** | **NVIDIA** | **CISCO** | **NOTES** |
| --- | --- | --- | --- |
| Single SKILL.md | Yes | Yes | Both support |
| Single file | Yes | Via `--skill-file` | — |
| Single directory | Yes | Yes | Both support |
| Multiple skills | Yes (directory) | Yes (`scan-all`) | — |
| Recursive directory | Yes | Yes (`--recursive`) | — |
| ZIP | Yes | Yes | — |
| GitHub | Yes | Yes (`scan-repo`) | — |
| Git | Yes | NOT VERIFIED | — |
| HTTP URL | Yes | NOT VERIFIED | — |
| Private repository | NOT VERIFIED | NOT VERIFIED | — |
| Custom metadata | Yes | Yes (`--skill-file`) | — |
| Custom rules | NOT VERIFIED | Yes (`--custom-rules`) | Cisco only |
| Policy | NOT VERIFIED | Yes (`--policy`) | Cisco only |
| Configuration file | Yes (`.env`) | Yes (policy) | — |
| Environment variables | Yes | Yes | — |
| API key | Yes | Yes | — |
| LLM | Yes | Yes | — |
| Behavioral analysis | NOT VERIFIED | Yes (`--use-behavioral`) | Cisco only |

---

## **Side-by-Side Output Comparison**

| **OUTPUT** | **NVIDIA** | **CISCO** | **MACHINE READABLE** | **RECOMMENDED** |
| --- | --- | --- | --- | --- |
| Terminal | Yes | Yes | No | No |
| JSON | Yes | Yes | Yes | **Yes** |
| Markdown | Yes | Yes | No | No |
| SARIF | Yes | Yes | Yes | **Yes** |
| HTML | No | Yes | No | No |
| Table | No | Yes | No | No |

## **Complete Input/Output Reference Table**

| **Input Type** | **NVIDIA Command** | **Cisco Command** |
| --- | --- | --- |
| Local skill directory | `skillspector scan ./my-skill/ --no-llm` | `skill-scanner scan ./my-skill` |
| Single SKILL.md | `skillspector scan ./my-skill/SKILL.md --no-llm` | `skill-scanner scan ./my-skill --skill-file SKILL.md` |
| Custom metadata file | N/A | `skill-scanner scan ./my-skill --skill-file README.md` |
| ZIP file | `skillspector scan ./my-skill.zip --no-llm` | `skill-scanner scan ./my-skill.zip` |
| TAR file | NOT VERIFIED | `skill-scanner scan ./my-skill.tar` |
| Git repository | `skillspector scan https://github.com/user/repo --no-llm` | `skill-scanner scan-repo owner/repo` |
| File URL | `skillspector scan file:///path/to/skill --no-llm` | NOT VERIFIED |
| ZIP URL | `skillspector scan https://example.com/skill.zip --no-llm` | NOT VERIFIED |
| Multiple skills | `skillspector scan ./all-skills/ --no-llm` | `skill-scanner scan-all ./skills` |
| Recursive scan | `skillspector scan ./skills/ --no-llm` | `skill-scanner scan-all ./skills --recursive` |
| Lenient mode | N/A | `skill-scanner scan ./dir --lenient` |
| Baseline suppression | `skillspector scan ./my-skill/ --baseline baseline.yaml` | N/A |
| JSON output | `skillspector scan ./my-skill/ --format json` | `skill-scanner scan ./my-skill --format json` |
| SARIF output | `skillspector scan ./my-skill/ --format sarif` | `skill-scanner scan ./my-skill --format sarif` |
| Markdown output | `skillspector scan ./my-skill/ --format markdown` | `skill-scanner scan ./my-skill --format markdown --detailed` |
| HTML output | N/A | `skill-scanner scan ./my-skill --format html` |
| Table output | N/A | `skill-scanner scan-all ./skills --format table` |
| LLM analysis | `skillspector scan ./my-skill/` (with API key) | `skill-scanner scan ./my-skill --use-llm` |
| Behavioral analysis | NOT VERIFIED | `skill-scanner scan ./my-skill --use-behavioral` |
| Policy | N/A | `skill-scanner scan ./my-skill --policy strict` |
| Custom rules | N/A | `skill-scanner scan ./my-skill --custom-rules ./rules/` |
| Cross-skill overlap | N/A | `skill-scanner scan-all ./skills --check-overlap` |
| CI/CD gate | `skillspector scan ./my-skill/ --fail-on-findings` | `skill-scanner scan ./my-skill --fail-on-severity high` |