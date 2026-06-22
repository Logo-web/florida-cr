import lief
import sys
import random
import os


def log_color(msg):
    print(f"\033[1;31;40m{msg}\033[0m")


if __name__ == "__main__":
    input_file = sys.argv[1]
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    log_color(f"[*] Patch agent: {input_file}")
    binary = lief.parse(input_file)
    if not binary:
        log_color("[*] Not elf, exit")
        sys.exit()

    # --- 1. symbol table renames (lief keeps .dynsym/.dynstr/hash consistent) ---
    rfrida = "".join(random.sample(charset, 5))
    rgum = "".join(random.sample(charset, 3))
    sym_count = 0
    for symbol in binary.symbols:
        if symbol.name == "frida_agent_main":
            symbol.name = "main"
            sym_count += 1
            continue
        n = symbol.name
        if "frida" in n:
            n = n.replace("frida", rfrida)
        if "gum" in n:
            n = n.replace("gum", rgum)
        if n != symbol.name:
            symbol.name = n
            sym_count += 1
    log_color(f"[*] renamed {sym_count} symbols (frida->{rfrida}, gum->{rgum})")

    # --- 2. reverse signature strings in .rodata (same length, consistent) ---
    # NOT touching protocol strings re.frida.* / frida:rpc (handled via context skip).
    # NOTE: do NOT reverse bare "Frida"/"frida" in .rodata — it corrupts the
    # GDBus interface re.frida.AgentSessionProvider and breaks server<->agent.
    # gum/Gum are NOT protocol-relevant, so they are safe to scrub.
    fixed_tokens = [
        "FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript",
        "GObject", "GThread", "GModule", "GMainContext",
        "GMainLoop", "GDBusConnection", "GLib", "glib", "gobject", "Gum",
    ]
    ctx_count = {}
    for section in binary.sections:
        if section.name != ".rodata":
            continue
        for patch_str in fixed_tokens:
            for addr in section.search_all(patch_str):
                patch = [ord(c) for c in patch_str[::-1]]
                binary.patch_address(section.file_offset + addr, patch)
                ctx_count[patch_str] = ctx_count.get(patch_str, 0) + 1
        # bare lowercase gum (NOT frida — protocol): reverse all occurrences
        for addr in section.search_all("gum"):
            binary.patch_address(section.file_offset + addr, [ord(c) for c in "mug"])
            ctx_count["gum"] = ctx_count.get("gum", 0) + 1
    log_color(f"[*] reversed rodata strings: {ctx_count}")

    binary.write(input_file)

    # --- 3. thread names (kernel comm, set via the static strings) ---
    for t, l in [("gum-js-loop", 11), ("gmain", 5), ("gdbus", 5), ("pool-frida", 10)]:
        r = "".join(random.sample("abcdefghijklmnopqrstuvwxyz", l))
        os.system(f"sed -b -i s/{t}/{r}/g {input_file}")

    log_color("[*] Patch Finish")
