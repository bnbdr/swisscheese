import struct
from io import BytesIO, StringIO

opcodes = {
    'OP_ADD_M': (32, 1),
    'OP_AND': (1, 0),
    'OP_BITWISE_AND': (5, 0),
    'OP_BITWISE_NOT': (4, 0),
    'OP_BITWISE_OR': (6, 0),
    'OP_BITWISE_XOR': (7, 0),
    'OP_CALL': (15, 1),
    'OP_CLEAR_M': (31, 1),
    'OP_CONTAINS': (40, 0),
    'OP_COUNT': (20, 0),
    'OP_DBL_ADD': (126, 0),
    'OP_DBL_DIV': (129, 0),
    'OP_DBL_EQ': (120, 0),
    'OP_DBL_GE': (125, 0),
    'OP_DBL_GT': (123, 0),
    'OP_DBL_LE': (124, 0),
    'OP_DBL_LT': (122, 0),
    'OP_DBL_MINUS': (130, 0),
    'OP_DBL_MUL': (128, 0),
    'OP_DBL_NEQ': (121, 0),
    'OP_DBL_SUB': (127, 0),
    'OP_ENTRYPOINT': (39, 0),
    'OP_ERROR': (0, 0),
    'OP_FILESIZE': (38, 0),
    'OP_FOUND': (22, 0),
    'OP_FOUND_AT': (23, 0),
    'OP_FOUND_IN': (24, 0),
    'OP_HALT': (255, 0),
    'OP_IMPORT': (42, 1),
    'OP_INCR_M': (30, 1),
    'OP_INDEX_ARRAY': (19, 0),
    'OP_INIT_RULE': (28, 2),
    'OP_INT16': (241, 0),
    'OP_INT16BE': (247, 0),
    'OP_INT32': (242, 0),
    'OP_INT32BE': (248, 0),
    'OP_INT8': (240, 0),
    'OP_INT8BE': (246, 0),
    'OP_INT_ADD': (106, 0),
    'OP_INT_DIV': (109, 0),
    'OP_INT_EQ': (100, 0),
    'OP_INT_GE': (105, 0),
    'OP_INT_GT': (103, 0),
    'OP_INT_LE': (104, 0),
    'OP_INT_LT': (102, 0),
    'OP_INT_MINUS': (110, 0),
    'OP_INT_MUL': (108, 0),
    'OP_INT_NEQ': (101, 0),
    'OP_INT_SUB': (107, 0),
    'OP_INT_TO_DBL': (11, 1),
    'OP_JFALSE': (44, 1),
    'OP_JLE': (37, 1),
    'OP_JNUNDEF': (36, 1),
    'OP_JTRUE': (45, 1),
    'OP_LENGTH': (21, 0),
    'OP_LOOKUP_DICT': (43, 0),
    'OP_MATCHES': (41, 0),
    'OP_MATCH_RULE': (29, 1),
    'OP_MOD': (10, 0),
    'OP_NOP': (254, 0),
    'OP_NOT': (3, 0),
    'OP_OBJ_FIELD': (18, 1),
    'OP_OBJ_LOAD': (16, 1),
    'OP_OBJ_VALUE': (17, 0),
    'OP_OF': (26, 0),
    'OP_OFFSET': (25, 0),
    'OP_OR': (2, 0),
    'OP_POP': (14, 0),
    'OP_POP_M': (33, 1),
    'OP_PUSH': (13, 1),
    'OP_PUSH_M': (34, 1),
    'OP_PUSH_RULE': (27, 1),
    'OP_SHL': (8, 0),
    'OP_SHR': (9, 0),
    'OP_STR_EQ': (140, 0),
    'OP_STR_GE': (145, 0),
    'OP_STR_GT': (143, 0),
    'OP_STR_LE': (144, 0),
    'OP_STR_LT': (142, 0),
    'OP_STR_NEQ': (141, 0),
    'OP_STR_TO_BOOL': (12, 0),
    'OP_SWAPUNDEF': (35, 1),
    'OP_UINT16': (244, 0),
    'OP_UINT16BE': (250, 0),
    'OP_UINT32': (245, 0),
    'OP_UINT32BE': (251, 0),
    'OP_UINT8': (243, 0),
    'OP_UINT8BE': (249, 0)}


def get_string_buf(val, t):
    sbuf = b''
    assert t in ['wide', 'ascii'], "bad type {}".format(t)

    separator = ''
    if t == 'wide':
        separator = '\0'

    val = val[1:-1]  # remove quoates from buffer
    for c in val:
        sbuf += c+separator

    sbuf += '\0' + separator
    return sbuf

def make_c_str(s):
    return get_string_buf("'{}'".format(s), 'ascii')

def make_wide_c_str(s):
    return get_string_buf("'{}'".format(s), 'wide')
    
class YaraAssembler(object):
    END_OF_CODE = opcodes['OP_HALT']

    @classmethod
    def build(cls, source, preprocessor={}, version=None):
        return cls._build(opcodes, source.splitlines(), preprocessor, version)

    @classmethod
    def _build(cls, opcodes, inf, preprocessor, version):

        comment = ';'
        lc = 0
        strings = []
        ouf = BytesIO()
        relocs = []

        for l in inf:
            lc += 1
            lparts = l.split()
            
            if not l or l[0] == comment:
                continue 
            lparts = lparts[:lparts.index(
                comment)] if comment in lparts else lparts
            if not lparts:
                continue

            assert len(lparts) in [
                1, 3, 5], 'unsupported line {} {}'.format(lc, lparts)
            opname = lparts[0]
            operands = []

            assert opname.startswith(
                'OP_'), 'not beginning with opcode {}: {}'.format(lc, lparts)
            assert opname in opcodes, 'not in opcode table {}: {}'.format(
                lc, lparts)

            val, operand_count = opcodes[opname]

            for i in range(1, len(lparts), 2):
                m = lparts[i].lower()
                v = lparts[i+1]
                assert m in ['raw', 'reloc', 'ascii', 'wide'], 'unsupported mode: `{}` {} {}'.format(
                    m, lc, lparts)

                reloc_addr = ouf.tell() + 1 + ((i-1)*8)
                if m in ['ascii', 'wide']:
                    relocs.append(reloc_addr)
                    strings.append(
                        (reloc_addr, get_string_buf(v, m)))
                    v = 0  # to be patched later
                else:
                    v = int(v, 0)
                    if m == 'reloc':
                        if lparts[i+1][0] in ['+']: # support for jmps relative (in bytes)
                            v+= reloc_addr + operand_count*8
                        relocs.append(reloc_addr)
                operands.append(v)

            
            assert len(operands) == operand_count, 'bad operand count @ {}:"{}"'.format(lc, l)

            form = '<B'
            if operand_count:
                if operand_count > 1:
                    form += str(operand_count)
                    assert len(operands) == operand_count,'ff'
                form += 'Q'

            if len(lparts) > 2:
                assert lparts[1]
            buf = struct.pack(form, val, *operands)
            ouf.write(buf)

        eob = ouf.tell()
        for addr_in_buf, raw_buf in strings:
            ouf.seek(eob)
            offset = eob
            ouf.write(raw_buf)
            eob = ouf.tell()
            ouf.seek(addr_in_buf)
            ouf.write(struct.pack('<Q', offset))

        ouf.seek(0)

        # raw_input(relocs)
        return ouf.read(), relocs
