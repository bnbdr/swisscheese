import sys
import os
import argparse


from assembler import YaraAssembler
from yara_types import YaraRule



def build(version, asm_code, preprocessor_definitions=None):
    bytecode, relocations = YaraAssembler.build(
        asm_code, preprocessor_definitions)

    rule = YaraRule(version)
    rule.addCode(bytecode, relocations)
    return rule.compile()


def cheese():
    return r"""
    Swiss         
         _-""-.
      .-"      "-.
     |""--..      '-.
     |      ""--..   '-.
     |.-. .-".    ""--..".
     |'./  -_'  .-.      |
     |      .-. '.-'   .-'
     '--..  '.'    .-  \-.
          ""--..   '_'   :
                ""--..   |
    Cheese            ""-' 

"""

if __name__ == '__main__':
    DEFAULT_ASM_FILE = 'swisscheese.yarasm'
    DEFAULT_OUT_FILE = 'swisscheese.rule'
    SUPPORTED_VERSIONS = [('3.7.1', 0x1020)]

    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-y', '--yara-asm', type=argparse.FileType('r'), default=DEFAULT_ASM_FILE,
                        help='yara asm file, defaults to "{}"'.format(DEFAULT_ASM_FILE))

    parser.add_argument('-v', '--target-version', choices=[vtup[0] for vtup in SUPPORTED_VERSIONS],
                        default=SUPPORTED_VERSIONS[0][0], help='yara version')

    parser.add_argument('-o', '--output', type=argparse.FileType('wb'),
                        default=DEFAULT_OUT_FILE, help='defaults to "{}"'.format(DEFAULT_OUT_FILE))

    # TODO: add preprocessor arg
    # TODO: implement preprocessor in assembler

    args = parser.parse_args()
    args.target_version = [
        tup[1] for tup in SUPPORTED_VERSIONS if tup[0] == args.target_version][0]
    output = build(args.target_version, args.yara_asm.read())
    args.output.write(output)

    print cheese()
    print 'saved to: {}'.format(args.output.name)
