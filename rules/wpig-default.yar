rule WPIG_PHP_Webshell_Suspicious_Functions {
    meta:
        description = "Suspicious PHP webshell-style function usage"
        author = "WP Intelligence Graph"
    strings:
        $a = "eval(" nocase
        $b = "base64_decode(" nocase
        $c = "shell_exec(" nocase
        $d = "passthru(" nocase
        $e = "gzinflate(" nocase
    condition:
        any of them
}

rule WPIG_PHP_Upload_Backdoor_Indicators {
    meta:
        description = "Common PHP backdoor request variable patterns"
        author = "WP Intelligence Graph"
    strings:
        $a = "$_POST" nocase
        $b = "$_REQUEST" nocase
        $c = "$_COOKIE" nocase
        $d = "assert(" nocase
        $e = "preg_replace" nocase
    condition:
        2 of them
}


rule WPIG_Webshell_Family_Strings {
    meta:
        description = "Common webshell and fake file-manager family strings"
        author = "WP Intelligence Graph"
    strings:
        $wso = "WSO" nocase
        $c99 = "c99shell" nocase
        $r57 = "r57shell" nocase
        $fm = "FilesMan" nocase
        $indo = "IndoXploit" nocase
        $mini = "Mini Shell" nocase
        $cmd = "cmd=" nocase
        $pass = "pass=" nocase
    condition:
        any of them
}

rule WPIG_C2_Callbacks_And_Payload_Fetchers {
    meta:
        description = "Suspicious callback or payload retrieval domains"
        author = "WP Intelligence Graph"
    strings:
        $telegram = "api.telegram.org" nocase
        $discord = "discord.com/api/webhooks" nocase
        $discord2 = "discordapp.com/api/webhooks" nocase
        $pastebin = "pastebin.com" nocase
        $githubraw = "raw.githubusercontent.com" nocase
        $gist = "gist.githubusercontent.com" nocase
        $onion = ".onion" nocase
    condition:
        any of them
}

rule WPIG_AI_Era_Prompt_Injection_Strings {
    meta:
        description = "Prompt injection or AI endpoint risk strings"
        author = "WP Intelligence Graph"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "system prompt" nocase
        $c = "jailbreak" nocase
        $d = "prompt injection" nocase
        $e = "api.openai.com" nocase
        $f = "api.anthropic.com" nocase
        $g = "HuggingFace" nocase
    condition:
        any of them
}

