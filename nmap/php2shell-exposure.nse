-- Standalone release: copy this file to any location and invoke it with
-- Nmap. It uses only NSE libraries bundled with a standard Nmap install.
description = [[
Reports likely PHP2Shell exposure (CVE-2026-109618 and CVE-2026-109619)
when an HTTP response discloses a PHP runtime version below the first upstream
fixed release. This is a banner-based exposure check, not an exploit test, and
never confirms that a target is vulnerable. Only one GET is sent to the chosen
path; redirects are not followed.

The first upstream fixed releases are PHP 8.2.35, 8.3.36, 8.4.27, and 8.5.12.
Older vendor packages may contain backported fixes without changing the
upstream version shown in an HTTP header.

Use --script-args php2shell.path=/path/to/a/php/page to inspect a specific page.
No output means no below-fix PHP version was disclosed; it does not establish
that the serving runtime is patched.
]]

---
-- @args php2shell.path Origin-relative path to request. Defaults to
-- <code>/</code>.
--
-- @usage
-- nmap -sV -p 80,443 --script ./php2shell-exposure.nse \
--   --script-args 'php2shell.path=/index.php' <target>
--
-- @output
-- | php2shell-exposure:
-- |   VULNERABLE:
-- |   PHP2Shell potential exposure by disclosed PHP version
-- |     State: LIKELY VULNERABLE
-- |     IDs:  CVE:CVE-2026-109618
-- |     Risk factor: High
-- |       The response disclosed a PHP version below the first upstream fixed
-- |       release. Banner evidence alone cannot confirm either vulnerability.
-- |     Check results:
-- |       request_path=/index.php
-- |       http_status=200
-- |       evidence[1].header_source=X-Powered-By
-- |       evidence[1].raw_version=8.5.11-1+deb12u1
-- |       evidence[1].assessment=below upstream fix 8.5.12
-- |     Extra information:
-- |_      Vendor packages may backport fixes without changing the disclosed
-- |       upstream version; verify the serving runtime and package provenance.

author = "nbehar"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local vulns = require "vulns"

portrule = shortport.http

local FIXED_RELEASES = {
  [2] = { patch = 35, version = "8.2.35" },
  [3] = { patch = 36, version = "8.3.36" },
  [4] = { patch = 27, version = "8.4.27" },
  [5] = { patch = 12, version = "8.5.12" }
}

local BACKPORT_CAVEAT =
  "Vendor packages may backport fixes without changing the " ..
  "disclosed upstream " ..
  "version; verify the serving runtime and package provenance."

local function is_prerelease(suffix)
  local qualifier = suffix:lower():match("^[%.%+~%-]*(.*)$") or ""
  return qualifier:match("^rc") ~= nil or
    qualifier:match("^alpha") ~= nil or
    qualifier:match("^beta") ~= nil or
    qualifier:match("^dev") ~= nil
end
local function classify(raw_version)
  local major, minor, patch, suffix =
    raw_version:match("^(%d+)%.(%d+)%.(%d+)(.*)$")
  if not major then
    return false, "unassessed malformed version token"
  end

  major, minor, patch = tonumber(major), tonumber(minor), tonumber(patch)
  local prerelease = is_prerelease(suffix)

  if major < 5 or (major == 5 and minor < 4) then
    return false, "outside the published affected-version range"
  end

  if major < 8 or (major == 8 and minor < 2) then
    return true, "end-of-life upstream branch; verify vendor backports"
  end

  if major == 8 and FIXED_RELEASES[minor] then
    local fixed = FIXED_RELEASES[minor]
    if patch < fixed.patch then
      return true, "below upstream fix " .. fixed.version
    end
    if patch == fixed.patch and prerelease then
      return true, "prerelease preceding final upstream fix " .. fixed.version
    end
    if prerelease then
      return false, "unassessed prerelease above upstream fix " .. fixed.version
    end
    return false, "at or above upstream fix " .. fixed.version
  end

  return false, "branch outside the published fixed-release matrix"
end

local function collect_versions(response)
  local observations = {}

  local function inspect_header(source, value)
    for raw_version in value:gmatch(
      "[Pp][Hh][Pp]/(%d+%.%d+%.%d+[%w%.%+~%-]*)") do
      local likely, assessment = classify(raw_version)
      observations[#observations + 1] = {
        source = source,
        raw_version = raw_version,
        likely = likely,
        assessment = assessment
      }
    end
  end

  for _, line in ipairs(response.rawheader or {}) do
    local source, value = line:match("^%s*([^:]+)%s*:%s*(.*)$")
    if source and value then
      local normalized = source:lower()
      if normalized == "x-powered-by" or normalized == "server" then
        inspect_header(source, value)
      end
    end
  end

  -- rawheader normally exists and preserves duplicate fields. Retain this
  -- fallback for HTTP handlers that provide only the normalized header map.
  if #observations == 0 then
    for _, source in ipairs({"x-powered-by", "server"}) do
      local value = response.header and response.header[source]
      if type(value) == "string" then
        inspect_header(source, value)
      end
    end
  end

  return observations
end

action = function(host, port)
  local path = stdnse.get_script_args("php2shell.path") or "/"
  if type(path) ~= "string" or path:sub(1, 1) ~= "/" or
    path:sub(1, 2) == "//" or path:find("[\r\n]") then
    return "php2shell.path must be an origin-relative path beginning with " ..
      "one / and must not contain CR or LF"
  end

  local response = http.get(host, port, path, {
    max_body_size = 1024,
    truncated_ok = true,
    redirect_ok = false
  })
  if not response or not response.status then
    return nil
  end

  local observations = collect_versions(response)
  local has_likely = false
  for _, observation in ipairs(observations) do
    if observation.likely then
      has_likely = true
      break
    end
  end
  if not has_likely then
    return nil
  end

  local check_results = {
    "request_path=" .. path,
    "http_status=" .. tostring(response.status)
  }
  for index, observation in ipairs(observations) do
    local prefix = string.format("evidence[%d].", index)
    check_results[#check_results + 1] =
      prefix .. "header_source=" .. observation.source
    check_results[#check_results + 1] =
      prefix .. "raw_version=" .. observation.raw_version
    check_results[#check_results + 1] =
      prefix .. "assessment=" .. observation.assessment
  end

  local vulnerability = {
    title = "PHP2Shell potential exposure by disclosed PHP version",
    state = vulns.STATE.LIKELY_VULN,
    IDS = { CVE = "CVE-2026-109618" },
    risk_factor = "High",
    dates = {
      disclosure = { year = 2026, month = 10, day = 21 }
    },
    description = [[
The response disclosed a PHP version below the first upstream fixed release for
CVE-2026-109618 and CVE-2026-109619. Banner evidence can be stale, spoofed,
supplied by a proxy, or describe a different runtime, so this result does not
confirm either vulnerability.
]],
    check_results = check_results,
    extra_info = { BACKPORT_CAVEAT },
    references = {
      "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
      "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp"
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  return report:make_output(vulnerability)
end
