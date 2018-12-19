import cProfile
import itertools

class Scanner():
    def __init__(self, position, cycle_length, shift=True):
        '''
        Create a scanner and shift its cycle by an offset determined by its
        position and frequency. Shifting the cycle means we no longer care about
        the position of the scanner in the firewall.

        '''
        self._cycle = [1] + [0] * (cycle_length-1)
        if shift is True:
            self.shift_cycle(position)

    def __len__(self,):
        return len(self._cycle)

    def __iter__(self):
        for pos in self._cycle:
            yield pos

    def shift_cycle(self, position):
        '''
        Shift the cycle relative to its position. Allows for scanners of
        similar size or harmonic cycle times to be merged/flattened into a
        single scanner. Removes the need to look ahead from the start time to
        see if a packet will pass the scanner.
        '''
        self._cycle = [0] * len(self)
        offset = 0 - (position % len(self))
        if offset < 0:
            offset += len(self)
        self._cycle[offset] = 1

    def merge(self, scanner):
        '''
        Merge the passed scanner's cycle into this scanner.
        '''
        self._cycle = tuple((max(v) for v in zip(scanner, self)))


class Firewall():
    def __init__(self, filepath):
        '''
        From a firewall input file, create a firewall's scanners.

        '''
        self.scanners = {}
        with open(filepath) as f:
            for line in f:
                scanner_pos, scanner_height = map(int, line.strip().split(': '))
                scanner_freq = 2 * (scanner_height - 1)
                scanner = Scanner(scanner_pos, scanner_freq)
                self.add_scanner(scanner)

        self.optimize()

    def __iter__(self):
        for scanner in self.scanners.values():
            yield itertools.cycle(scanner)

    def add_scanner(self, scanner):
        if len(scanner) in self.scanners:
            self.scanners[len(scanner)].merge(scanner)
        else:
            self.scanners[len(scanner)] = scanner

    def optimize(self):
        """
        Merge small scanners into larger ones if possible to reduce number of
        scanners.
        """
        cycle_lengths = sorted(self.scanners.keys())
        cycle_max = max(cycle_lengths)
        for cycle_lenth in cycle_lengths:
            for factor in itertools.count(start=2):
                cycle_key = cycle_lenth * factor
                if cycle_key > cycle_max or not cycle_key in self.scanners:
                    break
                else:
                    expanded_scanner = list(self.scanners[cycle_lenth]) * factor
                    self.scanners[cycle_key].merge(expanded_scanner)
                    del self.scanners[cycle_lenth]
                    break


def find_start(firewall):
    '''
    Unpack scanners from a firewall and simulataneously step through them
    to find the minimum start time to get the packet through (aka all
    scanners are True.)

    '''
    for t_start, possible_solution in enumerate(zip(*firewall)):
        if 1 in possible_solution:
            continue
        else:
            return t_start


firewall = Firewall(filepath="./day13/input.txt")
cProfile.run('start = find_start(firewall)')
print(f'start at {start}')
