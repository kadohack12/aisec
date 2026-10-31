"""Expert Reverse Engineering (classe 07-reverseengineer).

Premier jalon: suite Radare2 (rabin2, radare2, rahash2, rasm2, radiff2),
suite Rizin (rizin, rz-hash, rz-find), debogueur GDB, desassembleur bddisasm,
identification de binaires (detect-it-easy) et analyse Android/Java
(apktool, dex2jar, jadx, androguard, baksmali, smali).
"""

from __future__ import annotations

from .base import Expert

REVERSE_EXPERT = Expert(
    name="reverse",
    description="Reverse engineering: desassemblage, debogage, decompilation, analyse Android.",
    system_prompt=(
        "Tu es un expert en reverse engineering. Tu choisis l'outil le plus adapte "
        "parmi rabin2, radare2, rahash2, rasm2, radiff2, rizin, rz-hash, rz-find, "
        "gdb, bddisasm, die, apktool, dex2jar, jadx, androguard, baksmali et smali, "
        "puis tu extrais les parametres exacts. Privilegie l'analyse statique en "
        "lecture seule; l'execution ou le debogage d'un binaire (gdb) et "
        "l'assemblage (smali) demandent une confirmation. N'execute jamais un "
        "binaire non fiable hors d'un environnement isole."
    ),
    tool_names=[
        "rabin2",
        "radare2",
        "rahash2",
        "rasm2",
        "radiff2",
        "rizin",
        "rz-hash",
        "rz-find",
        "gdb",
        "bddisasm",
        "die",
        "apktool",
        "dex2jar",
        "jadx",
        "androguard",
        "baksmali",
        "smali",
    ],
    routing_rules=(
        ("die", ("detect-it-easy", "detect it easy", "packer", "protecteur", "identifie le binaire", "quel packer")),
        ("radiff2", ("radiff2", "diff binaire", "comparer deux binaires", "comparer deux versions")),
        ("rahash2", ("rahash2", "hash du binaire", "empreinte du binaire")),
        ("rz-hash", ("rz-hash", "hash avec rizin")),
        ("rz-find", ("rz-find", "recherche dans le binaire", "cherche une chaine dans le binaire")),
        ("rasm2", ("rasm2", "assembler des instructions", "desassembler des octets")),
        ("bddisasm", ("bddisasm", "decode les instructions", "desassemble les octets")),
        ("gdb", ("gdb", "debogue", "deboguer", "debugger", "gef")),
        ("apktool", ("apktool", "decode l'apk", "decoder une apk", "ressources de l'apk")),
        ("dex2jar", ("dex2jar", "d2j-dex2jar", "convertir dex en jar")),
        ("jadx", ("jadx", "decompile l'apk", "decompiler une apk", "decompile le dex")),
        ("androguard", ("androguard", "analyse apk", "permissions de l'apk")),
        ("baksmali", ("baksmali", "desassemble le dex", "dex en smali")),
        ("smali", ("smali assemble", "assembler smali", "recompiler smali")),
        ("radare2", ("radare2", "r2 ", "desassemble", "desassembler", "analyse le binaire")),
        ("rizin", ("rizin", "rz-bin")),
        ("rabin2", ("rabin2", "imports", "exports", "sections", "symboles", "chaines du binaire", "en-tetes du binaire")),
    ),
    keywords=(
        "reverse",
        "reverse engineering",
        "desassemble",
        "desassembler",
        "desassemblage",
        "decompile",
        "decompiler",
        "decompilation",
        "debug",
        "debogage",
        "deboguer",
        "radare",
        "radare2",
        "rizin",
        "rabin2",
        "ghidra",
        "apk",
        "android",
        "dex",
        "smali",
        "jadx",
        "dex2jar",
        "androguard",
        "packer",
        "obfuscation",
        "opcode",
        "assembleur",
        "gdb",
        "bddisasm",
    ),
)
