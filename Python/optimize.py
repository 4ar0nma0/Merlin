import lief
import numpy as np
import sys
import resource
from macros import *

# Building dependency needs a bigger stack size
resource.setrlimit(resource.RLIMIT_STACK, (2**29,-1))
sys.setrecursionlimit(10000000)

# While the documentation says nop is r1 = r1
# in practice it does not work
# so we use `jmp 0` as nop
nop = '0500000000000000'


class Section:
    def __init__(self, section_data, name=None):
        self.data = []
        self.name = name

        section_data = str(section_data)
        assert len(section_data) % 16 == 0 and "Bytecode section length must be a multiple of 16"

        # self.data is a list of 16-byte instructions
        for i in range(len(section_data)//16):
            self.data.append(section_data[i * 16: (i+1) * 16])

        self.dependencies = [[set(), set()] for _ in range(len(self.data))]  # [dependency, is depended by]
        self.build_dependency()
        self.store_candidates = self.apply_constant_propagation()
        self.apply_compaction()
        self.apply_peephole()
        self.apply_superword_merge()


    # Constant propagation implementation
    def apply_constant_propagation(self):
        candidates = []
        store_candidates = []
        count = 0
        
        # Check for constant propagation candidates
        for i, insn in enumerate(self.data):
            opcode = int(insn[:2], 16)
            if opcode in [0xb7, 0xb4]:
                cp_flag = 1
                for j in self.dependencies[i][1]:
                    opcode2 = int(self.data[j][:2], 16)
                    if opcode2 & 0x07 != BPF_STX or len(self.dependencies[j][0]) != 1 or opcode2 in [0xdb, 0xc3]:
                        cp_flag = 0
                        break
                if cp_flag:
                    count += 1
                    candidates.append(i)
                    store_candidates += self.dependencies[i][1]

        # Apply constant propagation if possible
        for i in candidates:
            insn = self.data[i]
            for j in self.dependencies[i][1]:
                opcode = int(self.data[j][:2], 16)
                new_opcode = hex((opcode & 0xf8) | BPF_ST)[2:]
                self.data[j] = new_opcode + '0' + self.data[j][3:8] + insn[8:]
                self.dependencies[j][0] = set()
            self.data[i] = nop
            self.dependencies[i][1] = set()

        # print('Saved %s instructions with constant propagation' % len(candidates))
        return store_candidates


    # Code compaction implementation
    def apply_compaction(self):
        candidates = []
        count = 0

        # Find candidates for compaction
        for i, insn in enumerate(self.data):
            opcode = int(insn[:2], 16)
            if opcode == 0x67 and int(self.data[i + 1][:2], 16) == 0x77:
                if insn[8:] == '20000000' and self.data[i+1][8:] == '20000000':
                    count += 1
                    candidates.append(i)
        
        # Apply code compaction
        for i in candidates:
            target_reg = self.data[i][3]
            self.data[i] = 'bc' + target_reg + target_reg + '000000000000'
            self.data[i+1] = nop

        # print('Saved %s instructions with code compaction' % len(candidates))


    # Peephole optimization implementation
    def apply_peephole(self):
        candidates, candidate_masks = [], []

        # Find mask candidates
        # Immediate is considered a mask if they are monotonically increasing
        # E.g., 0x0000FFFF
        for i, insn in enumerate(self.data):
            opcode = int(insn[:2], 16)
            src = insn[2]
            if opcode == 0x18 and int(self.data[i + 1][:2], 16) == 0x00 and src == '0':  # Load imm 64
                insn2 = self.data[i + 1]
                imm2 = insn2[14:16] + insn2[12:14] + insn2[10:12] + insn2[8:10]
                if int(imm2, 16) != 0:
                    continue
                imm = insn[14:16] + insn[12:14] + insn[10:12] + insn[8:10]
                imm = bin(int(imm, 16))[2:]

                mask_flag = 1
                for j in range(len(imm) - 1):
                    if imm[j] < imm[j + 1]:
                        mask_flag = 0
                if not mask_flag or '1' not in imm:
                    continue
                candidate_masks.append(i)

        # Find the candidates from mask candidates
        for mask in candidate_masks:
            for item in self.dependencies[mask][1]:
                # check if this is a shift right
                opcode = int(self.data[item][:2], 16)

                if opcode != 0x5f:
                    continue
                flag = 0
                for insn_next in self.dependencies[item][1]:
                    opcode_next = int(self.data[insn_next][:2], 16)
                    if opcode_next != 0x77:
                        flag = 1
                if flag:
                    continue

                # If the previous mov instruction is only used in this case
                # We can remove that as well
                include_pre = None
                if len(self.dependencies[item][0]) == 2:
                    pre = list(self.dependencies[item][0])
                    pre.remove(mask)
                    insn_pre = self.data[pre[0]]
                    opcode_pre = int(insn_pre[:2], 16)
                    if opcode_pre == 0xbf:
                        include_pre = pre[0]

                if include_pre:
                    insn_set = [mask, item, include_pre]
                else:
                    insn_set = [mask, item]

                candidates.append(insn_set)

        # Apply optimization
        for candidate in candidates:
            if len(candidate) == 3:
                new_insn = 'bc' + self.data[candidate[2]][2:4] + '000000000000'
            else:
                new_insn = 'bc' + self.data[candidate[1]][3] + self.data[candidate[1]][3] + '000000000000'
            for i in range(len(candidate)):
                if i == 1:
                    self.data[candidate[i]] = new_insn
                else:
                    self.data[candidate[i]] = nop
            self.data[candidate[0]+1] = nop

        # insn_gain = sum([len(candidate) for candidate in candidates]) if candidates else 0
        # print('Saved %s instructions with peephole optimization' % insn_gain)


    # Superword-level merge implementation
    def apply_superword_merge(self):
        
        # Get capacity of this offset
        # Since we need to align to it
        def get_cap(offset):
            if offset % 8 == 0:
                cap = 64
            elif offset % 4 == 0:
                cap = 32
            elif offset % 2 == 0:
                cap = 16
            else:
                cap = 8
            return cap

        # Get size related to this instruction
        def get_size(insn):
            mask = int(insn[:2], 16) & 0x18
            if mask == 0:
                return 32
            elif mask == 0x08:
                return 16
            elif mask == 0x10:
                return 8
            elif mask == 0x18:
                return 64

        def get_size_mask(size):
            if size == 8:
                mask = 0x10
            elif size == 16:
                mask = 0x08
            elif size == 32:
                mask = 0x00
            elif size == 64:
                mask = 0x18
            return mask

        # Get the candidates for memory merge
        def analyse(g, indices):
            c = []
            dsts = np.array([int(insn[3:4], 16) for insn in g])
            offs = np.array([self.to_signed(int(insn[6:8] + insn[4:6], 16), bits=16) for insn in g])
            sizes = np.array([get_size(insn) for insn in g])

            indices = np.array(indices)
            ind = np.lexsort((offs, dsts))
            reind = np.zeros_like(ind)
            reind[ind] = np.arange(len(ind))
            dsts, offs, sizes = dsts[ind], offs[ind], sizes[ind]

            g_, caps = [], []
            for j in range(len(dsts)):
                dst, off, size = dsts[j], offs[j], sizes[j]
                cap = get_cap(off)
                if not g_:
                    g_.append(indices[ind[j]])
                    caps.append(cap)
                for k in range(j+1, len(dsts)):
                    if dst == dsts[k] and off + size//8 ==offs[k] and size == sizes[k] and size * (k-j+1) <= cap:
                        off = offs[k]
                        g_.append(indices[ind[k]])
                    else:
                        if len(g_) == 8:
                            c.append(g_)
                        elif len(g_) >= 6:
                            c.append(g_[:4])
                            c.append(g_[4:6])
                        elif len(g_) >= 4:
                            c.append(g_[:4])
                        elif len(g_) >= 2:
                            c.append(g_[:2])
                        g_, caps = [], []
                        break
            return c

        candidates = []
        to_analyse = list(sorted(self.store_candidates))
        group = []
        indices = []
        flag = 0

        # Check all store instructions
        for i in range(len(to_analyse)-1):
            if not group:
                group.append(self.data[to_analyse[i]])
                indices.append(to_analyse[i])
                flag = 0

            # check if there are jmp and ldx in two adjacent stx
            for insn in self.data[to_analyse[i]+1: to_analyse[i+1]]:
                opcode = int(insn[:2], 16)
                if opcode & 0x07 in [BPF_LDX, BPF_JMP, BPF_JMP32]:
                    # stop updating and start analyzing current candidate list
                    if len(group) >= 2:
                        candidate = analyse(group, indices)
                        if candidate:
                            candidates += candidate
                    group = []
                    indices = []
                    flag = 1
                    break
            if not flag:
                group.append(self.data[to_analyse[i+1]])
                indices.append(to_analyse[i+1])

        # Eliminate improper candidates
        tmp = list()
        for i in range(len(candidates)):
            for j in range(len(candidates)):
                if set(candidates[i]) & set(candidates[j]) == set(candidates[i]) and i != j:
                    tmp.append(j)
        for item in sorted(set(tmp)).__reversed__():
            candidates.pop(item)
        
        # Check all candidates to see if they are mergeable
        # and store them to final_candidates for statistics
        final_candidates = []
        for candidate in candidates:
            # get the new size
            size = get_size(self.data[candidate[0]])
            new_size = size * len(candidate)
            assert new_size in [16, 32, 64]

            # get the new imm32
            new_imm = ''
            for i, idx in enumerate(candidate):
                insn = self.data[idx]
                new_imm += insn[8: 8+size//4]
            if len(new_imm) > 8:
                try:
                    assert int(new_imm[8:]) == 0
                except AssertionError:
                    continue
                new_imm = new_imm[:8]
            else:
                new_imm += '0' * (8-len(new_imm))
            final_candidates.append(candidate)

            # get the new opcode
            new_size_mask = get_size_mask(new_size)
            new_opcode = hex(BPF_MEM | new_size_mask | BPF_ST)[2:]
            new_reg_offset = self.data[candidate[0]][2:8]
            new_insn = new_opcode + new_reg_offset + new_imm
            for i in range(len(candidate)):
                if i == 0:
                    self.data[candidate[i]] = new_insn
                else:
                    self.data[candidate[i]] = nop

        # count = sum([len(item)-1 for item in final_candidates])
        # print('Saved %s instructions in superword-level merge' % count)
        return


    ###############################################
    # Building dependency
    # PRs are welcome
    ###############################################
    def analyse_insn(self, insn):
        opcode, src, dst, off, imm = insn
        updated_reg = -1
        updated_stack = []  # offset, size
        used_reg = []
        used_stack = []  # offset, size
        offset = None
        is_call = False
        is_exit = False
        LSB = opcode & 0x07
        if LSB in [BPF_ALU64, BPF_ALU]:
            MSB = opcode & 0xf0
            if MSB == ALU_END:  # byte exchange
                updated_reg = dst
                used_reg = [dst]
            elif MSB == ALU_MOV:  # byte exchange
                updated_reg = dst
                used_reg = [src] if opcode & BPF_X == BPF_X else []
            else:  # regular arithmetic
                if opcode & BPF_X == BPF_X:  # use reg
                    updated_reg = dst
                    used_reg = [dst, src]
                else:  # use imm
                    updated_reg = dst
                    used_reg = [dst]
        elif LSB in [BPF_JMP32, BPF_JMP]:
            MSB = opcode & 0xf0
            if MSB == JMP_CALL:
                if imm == 12:  # tail call
                    used_reg = [1, 2, 3]
                    used_stack = [0, 0]
                    # is_exit = True
                elif imm in [1, 3, 23, 44]:  # lookup, delete
                    used_reg = [1, 2]
                    updated_reg = 0
                elif imm in [2, 69]:  # update
                    used_reg = [1, 2, 3, 4]
                    updated_reg = 0
                elif imm in [4, 51]:  # lookup
                    used_reg = [1, 2, 3]
                    updated_reg = 0
                elif imm in [5, 7, 8]:  # lookup
                    updated_reg = 0
                elif imm in [9, 10, 11]:  # lookup
                    used_reg = [1, 2, 3, 4, 5]
                    updated_reg = 0
                else:
                    used_reg = [1, 2, 3, 4, 5]
                    # print(imm)
                    updated_reg = 0
                    is_call = True
            elif MSB == JMP_EXIT:
                used_reg = [0]
                is_exit = True
            elif opcode == 5:  # jump
                used_reg = []
                offset = off
            else:  # regular jump
                used_reg = [dst, src]
                offset = off
        elif LSB == BPF_STX:
            MSB = opcode & 0xe0
            if MSB in [BPF_MEMSX, BPF_MEM, BPF_ATOMIC]:
                size = int(2 ** ((opcode & 0x18) / 8 + 3))
                if dst == 10:
                    # todo: check if other regs are also stacks
                    updated_stack = [off, size]
                    used_reg = [src]
                else:
                    used_reg = [src]
            else:
                assert False
        elif LSB == BPF_ST:
            MSB = opcode & 0xe0
            if MSB in [BPF_MEMSX, BPF_MEM, BPF_ATOMIC]:
                size = int(2 ** ((opcode & 0x18) / 8 + 3))
                if dst == 10:
                    # todo: check if other regs are also stacks
                    updated_stack = [off, size]
            else:
                assert False
        elif LSB == BPF_LDX:
            #  LDX only has BPF_MEMSX and BPF_MEM
            MSB = opcode & 0xe0
            if MSB in [BPF_MEMSX, BPF_MEM]:
                size = int(2 ** ((opcode & 0x18) / 8 + 3))
                if src == 10:
                    # todo: check if other regs are also stacks
                    used_stack = [off, size]
                    updated_reg = dst
                else:
                    used_reg = [src]
                    updated_reg = dst
            else:
                assert False
        else:  # OPCODE.LSB = BPF_LD
            MSB = opcode & 0xe0
            if MSB in [BPF_IMM]:
                updated_reg = dst
            elif MSB in [BPF_ABS, BPF_IND]:
                updated_reg = dst
                used_reg = [src]
            else:
                assert False
        return updated_reg, updated_stack, used_reg, used_stack, offset, is_call, is_exit

    def to_signed(self, value, bits=32):
        if value & (1 << (bits - 1)):
            value -= 1 << bits
        return value

    def build_dependency(self):
        nodes = dict()  # len, next nodes
        nodes_len = dict()
        current_node = 0
        for i, insn in enumerate(self.data):
            if i == 2417:
                a = 0
            opcode = int(insn[:2], 16)
            off = insn[6:8] + insn[4:6]
            off = self.to_signed(int(off, 16), bits=16)
            MSB = opcode & 0xf0
            if opcode & 0x07 in [BPF_JMP, BPF_JMP32]:
                if MSB == JMP_CALL:
                    continue
                if MSB == JMP_EXIT:
                    nodes[current_node] = []
                elif opcode == 0x05:
                    nodes[current_node] = [i + off + 1]
                else:  # regular jump
                    nodes[current_node] = [i]
                    nodes[i] = [i + off + 1, i + 1]
                current_node = i+1

        nodes_rev = dict()
        for key in nodes.keys():
            if key != 0 and key not in nodes_rev.keys():
                nodes_rev[key] = set()
            for v in nodes[key]:
                if v in nodes_rev.keys():
                    nodes_rev[v].add(key)
                else:
                    nodes_rev[v] = set([key])

        all_nodes = list(nodes_rev.keys())
        all_nodes += [0, len(self.data)]
        all_nodes = sorted(all_nodes)
        for i in range(len(all_nodes)-1):
            nodes_len[all_nodes[i]] = (all_nodes[i+1] - all_nodes[i])

        nodes_rev = {k: list() for k in all_nodes}
        nodes_rev.pop(len(self.data))
        for node, node_len in nodes_len.items():
            for i in range(node_len):
                insn = self.data[node + i]
                opcode = int(insn[:2], 16)
                off = insn[6:8] + insn[4:6]
                off = self.to_signed(int(off, 16), bits=16)
                MSB = opcode & 0xf0
                if opcode & 0x07 in [BPF_JMP, BPF_JMP32]:
                    if MSB == JMP_CALL:
                        pass
                    elif MSB == JMP_EXIT:
                        continue
                    elif opcode == 0x05:
                        nodes_rev[node + i + off + 1].append(node)
                        continue
                    else:  # regular jump
                        # nodes_rev[node + i].append(node)
                        nodes_rev[node + i + off + 1].append(node + i)
                        nodes_rev[node + i + 1].append(node + i)
                        continue

                if i == node_len - 1 and node + node_len < len(self.data):
                    nodes_rev[node + node_len].append(node)

        for item in nodes_rev.keys():
            if item not in nodes.keys():
                nodes[item] = []
        for item in nodes_rev.keys():
            for n in nodes_rev[item]:
                if item not in nodes[n]:
                    nodes[n].append(item)

        self.update_property(base=0, nodes=nodes, nodes_rev=nodes_rev, nodes_len=nodes_len, nodes_done=None)

    def update_property(self, nodes, nodes_rev, nodes_len, nodes_done, regs=None, stacks=None, nodes_stats=None, reg_alias=None, base=0, loop_info=None, infer_only=0):

        data = self.data[base: base + nodes_len[base]]
        if stacks is None:
            stacks = {}
        if reg_alias is None:
            reg_alias = [None for _ in range(11)]
        if regs is None:
            regs = [list() for _ in range(11)]
            regs[1] = [-1]
            regs[10] = [-1]
        if nodes_stats is None:
            nodes_stats = dict()
        if nodes_done is None:
            nodes_done = set()
        for i, insn in enumerate(data):
            opcode = int(insn[:2], 16)
            if opcode == 0:
                continue
            src = int(insn[2:3], 16)
            dst = int(insn[3:4], 16)
            off = insn[6:8] + insn[4:6]
            off = self.to_signed(int(off, 16), bits=16)
            imm = insn[14:16] + insn[12:14] + insn[10:12] + insn[8:10]
            imm = self.to_signed(int(imm, 16), bits=32)
            updated_reg, updated_stack, used_reg, used_stack, offset, is_call, is_exit = self.analyse_insn((opcode, src, dst, off, imm))
            if opcode not in [0xbf, 0x07]:
                reg_alias[dst] = None
            if used_reg:
                for j in used_reg:
                    if j == 10:  # stack
                        reg_alias[dst] = 0
                    elif reg_alias[dst] is not None and opcode == 0x07:
                        reg_alias[dst] += imm
                    elif opcode != 0x85:
                        reg_alias[dst] = None

                    if not regs[j]:
                        continue
                    for item in regs[j]:
                        if reg_alias[j] is not None and reg_alias[j] != 0:
                            if reg_alias[j] in stacks.keys():
                                for k in stacks[reg_alias[j]]:
                                    self.dependencies[base + i][0].add(k)
                                    self.dependencies[k][1].add(base + i)
                            else:
                                stacks[reg_alias[j]] = [-1]
                                self.dependencies[base + i][0].add(-1)
                        self.dependencies[base + i][0].add(item)
                        self.dependencies[item][1].add(base + i)
            if updated_reg >= 0:
                regs[updated_reg] = [base + i]
            if is_call:
                for j in range(5):
                    regs[j+1] = list()
            if updated_stack:
                # todo: fix this
                stacks[updated_stack[0]] = [base + i]
            if used_stack:
                if used_stack[0] == 0:  # tail call
                    for item in stacks.keys():
                        for item2 in stacks[item]:
                            self.dependencies[base + i][0].add(item2)
                            self.dependencies[item2][1].add(base + i)
                elif used_stack[0] in stacks.keys():
                    for item in stacks[used_stack[0]]:
                        self.dependencies[base + i][0].add(item)
                        self.dependencies[item][1].add(base + i)
                else:
                    stacks[used_stack[0]] = [-1]
                    self.dependencies[base + i][0].add(-1)
            if is_exit:
                nodes_done.add(base)
                if len(nodes_done) >= len(nodes_rev.keys()):
                    return

        # Get new base if not done
        nodes_stats[base] = [regs, stacks]
        if infer_only:
            return regs, stacks
        nodes_done.add(base)

        new_base = 0
        new_regs = [list() for _ in range(11)]
        new_stack = dict()

        if loop_info:
            pre = set(nodes_rev[loop_info[0]])
            if pre & set(nodes_done) == pre:
                # pre = set(nodes_rev[loop_info[0]])
                new_regs = [list() for _ in range(11)]
                new_stack = dict()
                for item in pre:
                    for i in range(len(regs)):
                        new_regs[i] += nodes_stats[item][0][i]
                    item_stack = nodes_stats[item][1]
                    for k in item_stack.keys():
                        if k in new_stack.keys():
                            new_stack[k] += item_stack[k]
                        else:
                            new_stack[k] = item_stack[k]
                new_regs = [list(set(r)) for r in new_regs]
                new_stack = {r: list(set(new_stack[r])) for r in new_stack.keys()}

                new_regs, new_stack = self.update_property(nodes, nodes_rev, nodes_len, nodes_done, regs=new_regs, stacks=new_stack,
                                     nodes_stats=nodes_stats, reg_alias=reg_alias, base=loop_info[0],
                                     loop_info=loop_info, infer_only=1)

                continue_loop = 0
                for r0, r1 in zip(nodes_stats[loop_info[0]][0], new_regs):
                    if set(r0) != set(r1):
                        continue_loop = 1
                        break
                for stack_key in new_stack.keys():
                    if set(new_stack[stack_key]) != set(nodes_stats[loop_info[0]][1][stack_key]):
                        a, b = set(new_stack[stack_key]), set(loop_info[2][stack_key])
                        continue_loop = 1
                        break

                nodes_stats[loop_info[0]] = [new_regs, new_stack]
                nodes_done -= loop_info[3]
                loop_info[3] = set()
                if base in nodes_done:
                    nodes_done.remove(base)
                if not continue_loop:
                    if loop_info[4]:
                        loop_info[4][3].add(loop_info[0])
                    nodes_done.add(loop_info[0])
                    loop_info = loop_info[4]
                if loop_info:
                    self.update_property(nodes, nodes_rev, nodes_len, nodes_done, regs=new_regs, stacks=new_stack,
                                     nodes_stats=nodes_stats, reg_alias=reg_alias, base=loop_info[0], loop_info=loop_info)


            else:
                loop_info[3].add(base)

        for key in nodes_rev.keys():
            if loop_info:
                data = self.data[key: key + nodes_len[key]]
                if '9500000000000000' in data:
                    continue
            pre = set(nodes_rev[key])
            if key not in nodes_done and pre & nodes_done == pre:
                if key == 52:
                    a = 1
                new_regs = [list() for _ in range(11)]
                new_stack = dict()
                for item in pre:
                    for i in range(len(regs)):
                        new_regs[i] += nodes_stats[item][0][i]
                    item_stack = nodes_stats[item][1]
                    for k in item_stack.keys():
                        if k in new_stack.keys():
                            new_stack[k] += item_stack[k]
                        else:
                            new_stack[k] = item_stack[k]
                new_base = key
                new_regs = [list(set(r)) for r in new_regs]
                new_stack = {r: list(set(new_stack[r])) for r in new_stack.keys()}
        if new_base == 0 and len(nodes_done) != len(nodes_rev.keys()):
            # contains loops
            def get_loop(start, stop):
                if not nodes[start]:
                    return [-1]
                elif stop in nodes[start]:
                    return []
                else:
                    l = [start]
                    flag = 0
                    for item in nodes[start]:
                        if item in nodes_iterated:
                            continue
                        else:
                            nodes_iterated.append(item)
                        tmp = get_loop(item, stop)
                        if -1 not in tmp:
                            l += tmp
                            flag = 1
                    if not flag:
                        l = [-1]
                return list(set(l))

            new_base_candidates = set()
            for d in nodes_done:
                new_base_candidates |= set(nodes[d])
            new_base_candidates -= set(nodes_done)
            for c in new_base_candidates:
                nodes_iterated = []
                tmp = get_loop(c, c)
                if tmp and -1 not in tmp:
                    new_base = c
                    new_regs = [list() for _ in range(11)]
                    new_stack = dict()
                    pre = set(nodes_rev[new_base])
                    for item in pre:
                        if item not in nodes_stats.keys():
                            continue
                        for i in range(len(regs)):
                            new_regs[i] += nodes_stats[item][0][i]
                        item_stack = nodes_stats[item][1]
                        for k in item_stack.keys():
                            if k in new_stack.keys():
                                new_stack[k] += item_stack[k]
                            else:
                                new_stack[k] = item_stack[k]
                    new_regs = [list(set(r)) for r in new_regs]
                    new_stack = {r: list(set(new_stack[r])) for r in new_stack.keys()}
                    if loop_info:
                        loop_info = [new_base, new_regs, new_stack, set(), loop_info]
                    else:
                        loop_info = [new_base, new_regs, new_stack, set(), []]
                    break

        if new_base:
            self.update_property(nodes, nodes_rev, nodes_len, nodes_done, regs=new_regs, stacks=new_stack, nodes_stats=nodes_stats, reg_alias=reg_alias, base=new_base, loop_info=loop_info)

        return nodes_stats

    def dump(self):
        return bytearray(bytes.fromhex(''.join(self.data)))


class BPFProg():
    def __init__(self, path):
        self.bin = lief.parse(path)
        self.sections = dict()

        for sym_idx, symbol in enumerate(self.bin.symbols):
            if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC:
                section = symbol.section
                if section and len(bytes(section.content)) != 0:
                    self.sections[section.name] = Section(bytes(section.content).hex(), section.name)

                    # Writing modified section back to object
                    modified_content = self.sections[section.name].dump()
                    self.bin.symbols[sym_idx].section.content = memoryview(modified_content)
                    # End of writing

    def save(self, path):
        builder = lief.ELF.Builder(self.bin)
        builder.build()
        builder.write(path)


if __name__ == '__main__':
    prog = BPFProg('test.o')
    prog.save('test_optimized.o')