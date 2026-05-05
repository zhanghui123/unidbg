package com.github.unidbg.utils;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.Symbol;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.trace.text.DefaultJniParser;

import java.util.HashMap;
import java.util.Map;

public class SymbolResolver {
    private final Module module;
    private final Emulator<?> emulator;
    private final Map<Long, String> cache = new HashMap<>();
    private Map<Long, Integer> jniStubToIndex = null; // lazy init
    private static final long MAX_FUNC_SIZE = 0x10000;

    public SymbolResolver(Module module, Emulator<?> emulator) {
        this.module = module;
        this.emulator = emulator;
    }

    public String resolve(long address, long caller) {
        return cache.computeIfAbsent(address, addr -> {
            // Check JNI: target directly in SvcMemory (from blr)
            String jniName = resolveJniByAddr(addr);
            if (jniName != null) return appendCallerOffset(jniName, caller);

            long moduleOffset = addr - module.base;
            boolean inModule = moduleOffset >= 0 && moduleOffset < module.size;

            if (inModule) {
                Symbol sym = module.findClosestSymbolByAddress(addr, false);
                if (sym != null) {
                    long offset = addr - sym.getAddress();
                    if (offset <= MAX_FUNC_SIZE) {
                        String name = offset == 0 ? sym.getName() : String.format("%s + 0x%x", sym.getName(), offset);
                        return appendCallerOffset(name, caller);
                    }
                }
                String pltResult = resolvePlt(addr);
                if (pltResult != null) return appendCallerOffset(pltResult, caller);
                return appendCallerOffset(String.format("sub_%x", moduleOffset), caller);
            }

            Memory memory = emulator.getMemory();
            Module extModule = memory.findModuleByAddress(addr);
            if (extModule != null) {
                Symbol sym = extModule.findClosestSymbolByAddress(addr, false);
                if (sym != null) {
                    long offset = addr - sym.getAddress();
                    if (offset <= MAX_FUNC_SIZE) {
                        return appendCallerOffset(extModule.name + " " + (offset == 0 ? sym.getName() : String.format("%s + 0x%x", sym.getName(), offset)), caller);
                    }
                }
                return appendCallerOffset(String.format("%s sub_%x", extModule.name, addr - extModule.base), caller);
            }
            return null;
        });
    }

    private String appendCallerOffset(String name, long caller) {
        long callerOffset = caller - module.base;
        if (callerOffset >= 0 && callerOffset < module.size) {
            return name + String.format(" @0x%x", callerOffset);
        }
        return name;
    }

    private String resolveJniByAddr(long targetAddr) {
        try {
            SvcMemory svcMemory = emulator.getSvcMemory();
            if (svcMemory == null || targetAddr < svcMemory.getBase() || targetAddr >= svcMemory.getBase() + svcMemory.getSize()) {
                return null;
            }
            if (jniStubToIndex == null) {
                jniStubToIndex = buildJniStubMap();
            }
            Integer index = jniStubToIndex.get(targetAddr);
            if (index != null && index >= 0 && index < DefaultJniParser.JNI_METHODS.length) {
                return "JNI " + DefaultJniParser.JNI_METHODS[index];
            }
        } catch (Exception ignored) {}
        return null;
    }

    private Map<Long, Integer> buildJniStubMap() {
        Map<Long, Integer> map = new HashMap<>();
        try {
            Backend backend = emulator.getBackend();
            boolean is64Bit = emulator.is64Bit();
            int ptrSize = is64Bit ? 8 : 4;
            int reservedOffset = is64Bit ? 0x20 : 0x10;
            int implSize = is64Bit ? 0x750 : 0x3a8;
            SvcMemory svcMemory = emulator.getSvcMemory();
            long svcBase = svcMemory.getBase();
            int svcSize = svcMemory.getSize();
            for (long scanAddr = svcBase; scanAddr < svcBase + svcSize - implSize; scanAddr += 0x10) {
                byte[] ptrBytes = backend.mem_read(scanAddr + reservedOffset, ptrSize);
                long firstPtr = readPointer(ptrBytes, ptrSize);
                if (firstPtr < svcBase || firstPtr >= svcBase + svcSize) continue;
                byte[] ptrBytes2 = backend.mem_read(scanAddr + reservedOffset + ptrSize, ptrSize);
                long secondPtr = readPointer(ptrBytes2, ptrSize);
                if (secondPtr < svcBase || secondPtr >= svcBase + svcSize) continue;
                for (int off = reservedOffset; off < implSize; off += ptrSize) {
                    byte[] entry = backend.mem_read(scanAddr + off, ptrSize);
                    long entryPtr = readPointer(entry, ptrSize);
                    int index = off / ptrSize;
                    map.put(entryPtr, index);
                }
                break;
            }
        } catch (Exception ignored) {}
        return map;
    }

    private long readPointer(byte[] bytes, int ptrSize) {
        long val = 0;
        for (int i = ptrSize - 1; i >= 0; i--) {
            val = (val << 8) | (bytes[i] & 0xFFL);
        }
        return val;
    }

    private String resolvePlt(long pltAddr) {
        try {
            Backend backend = emulator.getBackend();
            boolean is64Bit = emulator.is64Bit();
            long offset = pltAddr - module.base;
            if (offset < 0 || offset > 0x800000) return null;
            int stubSize = is64Bit ? 16 : 12;
            byte[] stubCode = backend.mem_read(pltAddr, stubSize);
            if (stubCode == null) return null;
            long gotAddr = parsePltGotAddress(pltAddr, stubCode, is64Bit);
            if (gotAddr == 0) return null;
            int ptrSize = is64Bit ? 8 : 4;
            byte[] gotEntry = backend.mem_read(gotAddr, ptrSize);
            if (gotEntry == null) return null;
            long funcAddr = 0;
            for (int i = ptrSize - 1; i >= 0; i--) {
                funcAddr = (funcAddr << 8) | (gotEntry[i] & 0xFFL);
            }
            Memory memory = emulator.getMemory();

            // Check JNI: GOT points into SvcMemory
            String jniName = resolveJniByAddr(funcAddr);
            if (jniName != null) {
                return jniName;
            }

            Module funcModule = memory.findModuleByAddress(funcAddr);
            if (funcModule == null || funcModule == module) return null;
            Symbol funcSymbol = funcModule.findClosestSymbolByAddress(funcAddr, false);
            if (funcSymbol == null) return null;
            String name = funcSymbol.getName();
            if (name == null || name.isEmpty() || name.equals("start") || name.equals("_start")) return null;
            return funcModule.name + " " + name;
        } catch (Exception e) {
            return null;
        }
    }

    private long parsePltGotAddress(long pltAddr, byte[] stubCode, boolean is64Bit) {
        if (is64Bit) {
            if (stubCode.length < 16) return 0;
            int op0 = (stubCode[3] & 0xFF) << 24 | (stubCode[2] & 0xFF) << 16 | (stubCode[1] & 0xFF) << 8 | (stubCode[0] & 0xFF);
            int op1 = (stubCode[7] & 0xFF) << 24 | (stubCode[6] & 0xFF) << 16 | (stubCode[5] & 0xFF) << 8 | (stubCode[4] & 0xFF);
            if ((op0 & 0x9F000000) != 0x90000000) return 0;
            int immlo = (op0 >> 29) & 0x3;
            int immhi = (op0 >> 5) & 0x7FFFF;
            int imm21 = (immhi << 2) | immlo;
            long pageBase = (pltAddr & ~0xFFFL) + ((long) imm21 << 12);
            if ((op1 & 0xFFC00000) != 0xF9400000) return 0;
            int ldrImm12 = (op1 >> 10) & 0xFFF;
            return pageBase + ((long) ldrImm12 * 8);
        } else {
            if (stubCode.length < 12) return 0;
            int op0 = (stubCode[3] & 0xFF) << 24 | (stubCode[2] & 0xFF) << 16 | (stubCode[1] & 0xFF) << 8 | (stubCode[0] & 0xFF);
            int op1 = (stubCode[7] & 0xFF) << 24 | (stubCode[6] & 0xFF) << 16 | (stubCode[5] & 0xFF) << 8 | (stubCode[4] & 0xFF);
            if ((op0 & 0xFFFFF000) == 0xE28FC000) {
                int off0 = op0 & 0xFFF;
                if ((op1 & 0xFFFFF000) == 0xE28CC000) {
                    int off1 = op1 & 0xFFF;
                    long gotAddr = (pltAddr & ~0xFFFL) + off0 + off1;
                    int op2 = (stubCode[11] & 0xFF) << 24 | (stubCode[10] & 0xFF) << 16 | (stubCode[9] & 0xFF) << 8 | (stubCode[8] & 0xFF);
                    int ldrOff = op2 & 0xFFF;
                    return gotAddr + ldrOff + 4;
                }
            }
            return 0;
        }
    }
}