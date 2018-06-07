from io import BytesIO
from typedef import struct, union, pragma, BYTE, DWORD, WORD, QWORD, sizeof, offsetof
from assembler import make_c_str
from yara_hash import yr_hash


MAX_THREADS = 32
RULE_GFLAGS_NULL = 0x1000
EXTERNAL_VARIABLE_TYPE_NULL = 0
NO_RELOC_MAGIC = 0xFFFABADA
RELOCATIONS_END_MARKER = 0xFFFFFFFF
UNUSED = 0xFA

with pragma.pack(1):
    YR_HDR = struct([
        (BYTE[4], 'magic'),
        (DWORD, 'size'),
        struct([
            (WORD, 'max_threads'),
            (WORD, 'arena_ver')
        ], 'version')
    ])


pragma.pack.push(8)
YARA_RULES_FILE_HEADER = struct([
    (QWORD, 'rules_list_head'),
    (QWORD, 'externals_list_head'),
    (QWORD, 'code_start'),
    (QWORD, 'ac_match_table'),
    (QWORD, 'ac_transition_table'),
    (DWORD, 'ac_tables_size'),
])

YR_RULE = struct([
    (DWORD, 'g_flags'),
    (DWORD[MAX_THREADS],  't_flags'),
    (QWORD, 'identifier'),
    (QWORD, 'tags'),
    (QWORD, 'metas'),
    (QWORD, 'strings'),
    (QWORD, 'ns'),
    (QWORD, 'time_cost'),
])


YR_EXTERNAL_VARIABLE = struct([
    (DWORD, 'type'),
    union([
        (QWORD, 'i'),
        (QWORD, 'f'),
        (QWORD, 's'),
    ], 'value'),
    (QWORD, 'identifier')
])

YR_AC_MATCH_ENTRY = QWORD
YR_AC_MATCH_TABLE = struct([
    (YR_AC_MATCH_ENTRY[1], 'match'),
])


EMPTY_TRANSTION_TABLE = QWORD[256+1]# to make sure any MAX_UBYTE+1 value will still be within the table 
YR_NAMESPACE = struct([
    (DWORD[MAX_THREADS],  't_flags'),
    (QWORD, 'name')
])


pragma.pack.pop()


class YaraRule(object):

    def __init__(self, version, name='SwissCheese', ns='default'):

        self.rulename = name
        self.namespace = ns
        self.code_relocations = []
        self.target_version = version
        self.code = BytesIO()

    def addCode(self, bytecode, relocations):
        # offset = self.code.tell()
        offset = 0 
        assert self.code.tell() == 0, 'multiple code offsets not supported as of yet'
        self.code.write(bytecode)
        for r in relocations:
            self.code_relocations.append(offset + r)

    def compile(self, fix_hash=True):
        # TODO:  assert code[-1] == YaraAssembler.END_OF_CODE, "code doesn't end with END_OF_CODE opcode"
       
        self.code.seek(0)
        reloc_buffer = ''
        file_hash = 0
        ns_c_str = make_c_str(self.namespace)
        rulename_c_str = make_c_str(self.rulename)
        struct_relocations = []

        with pragma.pack(1):
            BODY = struct([
                (YARA_RULES_FILE_HEADER, 'rules_file_hdr'),
                (YR_RULE, 'rule'),
                (YR_RULE, 'nullrule'),
                (YR_EXTERNAL_VARIABLE, 'nullexternal'),
                (YR_NAMESPACE, 'namespace'),
                (BYTE[len(ns_c_str)], 'ns_name'),
                (BYTE[len(rulename_c_str)], 'rule_name'),
                (YR_AC_MATCH_TABLE, 'match_table'),
                (EMPTY_TRANSTION_TABLE, 'transition_table'),

            ])

        body = BODY()
        rulehdroffset = offsetof('rules_file_hdr', body)

        body.rules_file_hdr.rules_list_head = offsetof('rule', body)
        struct_relocations.append(
            rulehdroffset + offsetof('rules_list_head', YARA_RULES_FILE_HEADER))

        body.rules_file_hdr.externals_list_head = offsetof(
            'nullexternal', body)
        struct_relocations.append(
            rulehdroffset + offsetof('externals_list_head', YARA_RULES_FILE_HEADER))

        body.rules_file_hdr.ac_match_table = offsetof('match_table', body)
        struct_relocations.append(
            rulehdroffset + offsetof('ac_match_table', YARA_RULES_FILE_HEADER))

        body.rules_file_hdr.ac_transition_table = offsetof('transition_table', body)
        struct_relocations.append(
            rulehdroffset + offsetof('ac_transition_table', YARA_RULES_FILE_HEADER))

        file_code_start_offset = sizeof(body)
        body.rules_file_hdr.code_start = file_code_start_offset
        struct_relocations.append(
            rulehdroffset + offsetof('code_start', YARA_RULES_FILE_HEADER))


        body.rule.identifier = offsetof('rule_name', body)
        struct_relocations.append(
            offsetof('rule', body) + offsetof('identifier', YR_RULE))

        body.rule.ns = offsetof('namespace', body)
        struct_relocations.append(
            offsetof('rule', body) + offsetof('ns', YR_RULE))

        body.nullrule = BYTE(UNUSED)*sizeof(YR_RULE)
        body.nullrule.g_flags = RULE_GFLAGS_NULL
        body.ns_name = ns_c_str
        body.rule_name = rulename_c_str
        body.nullrule.g_flags = RULE_GFLAGS_NULL
        body.nullexternal = BYTE(UNUSED)*sizeof(YR_EXTERNAL_VARIABLE)
        body.nullexternal.type = EXTERNAL_VARIABLE_TYPE_NULL

        for r in struct_relocations:
            reloc_buffer += DWORD(r)

        self.code.seek(0)
        final_code_bytes = self.code.read()

        for r in self.code_relocations[:]:
            reloc_buffer += DWORD(file_code_start_offset + r )# add base of code
            patched = QWORD(file_code_start_offset + QWORD(final_code_bytes[r:r+8]))
            final_code_bytes = final_code_bytes[:r] + patched + final_code_bytes[r+8:]
       
        hdr = YR_HDR()

        body_bytes = bytes(body) + final_code_bytes
        if len(body_bytes) < 2048:
            padding = '\xCC' * (2048-len(body_bytes))
            body_bytes += padding

        # finalize
        hdr.magic = [ord(l) for l in 'YARA']
        hdr.version.max_threads = self.target_version & 0xFF
        hdr.version.arena_ver = (self.target_version & 0xFF00) >> 8
        hdr.size = len(body_bytes)

        hdr_bytes = bytes(hdr)
        file_hash = yr_hash(hdr_bytes)
        file_hash = yr_hash(body_bytes, file_hash)
        return hdr_bytes + body_bytes + reloc_buffer + DWORD(-1) + DWORD(file_hash)
