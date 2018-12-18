import cProfile
import itertools


def build_scanner(scanner_pos, scanner_height):
    '''
    Create a scanner. A scanner's cycle frequency is offset by its position so
    that an entire row of zipped scanners represents one start time run. False
    blocks a packet and True let's it past.
    
    '''
    freq = (scanner_height - 1) * 2
    scanner = [True] * freq
    cycle_offset_due_to_pos = 0 - scanner_pos%freq
    if cycle_offset_due_to_pos < 0:
        cycle_offset_due_to_pos += freq
    scanner[cycle_offset_due_to_pos] = False
    return scanner


def firewall_from_file(firewall_file):
    '''
    From a firewall input file, iterate back a firewall's scanners.

    '''
    with open(firewall_file) as f:
        for line in f:
            scanner_pos, scanner_height = map(int, line.strip().split(': '))
            scanner = build_scanner(scanner_pos, scanner_height)
            yield itertools.cycle(scanner)


def find_start(firewall):
    '''
    Unpack scanners from a firewall and simulataneously step through them
    to find the minimum start time to get the packet through (aka all
    scanners are True.)

    '''
    for t_start, possible_solution in enumerate(zip(*firewall)):
        if False in possible_solution:
            continue
        else:
            return t_start


cProfile.run('start = find_start(firewall_from_file("./day13/input.txt"))')
print(f'start at {start}')
