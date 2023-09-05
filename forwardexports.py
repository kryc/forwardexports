import os
import argparse
import logging
import pefile

#pylint: disable=logging-fstring-interpolation
#pylint: disable=missing-function-docstring
#pylint: disable=no-member

def main():
    parser = argparse.ArgumentParser(description='Generate the header file for forwarded exports')
    parser.add_argument('pefile', help='PE file to forward exports for')
    parser.add_argument('outfile', help='Output filename')
    parser.add_argument('--basename', help='Override basename for original PE')
    parser.add_argument('--pragma', action='store_true', help='Format output as pragmas')
    parser.add_argument('--loglevel', default='warning', help='Provide logging level')
    args = parser.parse_args()

    logging.basicConfig(level=args.loglevel.upper())

    if not os.path.isfile(args.pefile):
        logging.critical("File not found")
        return

    if args.basename is None:
        logging.info('Using target basename from input file')
        args.basename = os.path.basename(args.pefile)

    logging.info(f'Target basename: {args.basename}')

    outfile_ext = "." + args.outfile.split(".")[-1] if "." in args.outfile else None

    if outfile_ext is None:
        outfile_ext = ".h" if args.pragma else ".def"
    elif outfile_ext == ".def" and args.pragma:
        logging.warning("Setting outfile extension to .h")
        outfile_ext = ".h"
    elif outfile_ext == ".h" and not args.pragma:
        logging.warning("Setting outfile extension to .def")
        outfile_ext = ".def"

    args.outfile = ".".join(args.outfile.split(".")[:-1]) + outfile_ext

    # Strip the extension
    pefile_basename = os.path.basename(args.pefile)
    basename_no_ext = '.'.join(args.basename.split('.')[:-1])

    with open(args.outfile, 'wt', encoding='utf8') as fh:

        logging.info(f'Opening {pefile_basename}')
        with pefile.PE(args.pefile) as pe:
            if not hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
                logging.critical('[!] Specified pefile has no exported symbols')
                return

            if not args.pragma:
                fh.write("LIBRARY\n\nEXPORTS\n")

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                logging.info(f"{hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)}, {exp.name}, {exp.ordinal}")
                # name, ordinal, basename
                if args.pragma:
                    line = "#pragma comment(linker, \"/EXPORT:{0:s}={2:s}.#{1:d},@{1:d}\")"
                else:
                    line = "\t{0:s}={2:s}.@{1:d} @{1:d}"
                formatted = line.format(exp.name.decode('utf8'), exp.ordinal, basename_no_ext)
                fh.write(f"{formatted}\n")

if __name__ == "__main__":
    main()
