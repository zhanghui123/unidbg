package com.github.unidbg.trace.text;

import com.github.unidbg.*;
import com.github.unidbg.listener.TraceCodeListener;
import capstone.api.Instruction;
import capstone.api.RegsAccess;
import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.arm.backend.UnHook;

import com.github.unidbg.Symbol;
import com.github.unidbg.Module;
import com.github.unidbg.unwind.Unwinder;

import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Arrays;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Locale;
import java.util.ArrayDeque;
import java.util.Deque;

public class AssemblyCodeTextDumper implements CodeHook, TraceHook {

    private final Emulator<?> emulator;
    private final long traceBegin, traceEnd;
    private final Module[] traceModules;
    private final String[] traceModuleNames;
    private final TraceCodeListener listener;

    private final List<UnHook> unHooks = new ArrayList<>();

    private PrintStream redirect;
    private StringBuilder bufferedInstruction = null;
    private RegAccessPrinter lastInstructionWritePrinter = null;
    private Long lastAddress = null;
    private Long currentInstructionAddress = null;
    private final List<String> pendingMemoryDumps = new ArrayList<>();
    private String pendingCallLine = null;
    private int pltSkipCount = 0;
    private static final Logger log = LoggerFactory.getLogger(AssemblyCodeTextDumper.class);
    private static final int SYMBOL_MAX_OFFSET = Unwinder.SYMBOL_SIZE;
    
    private boolean debugSymbolResolution = false;
    
    public void setDebugSymbolResolution(boolean debug) {
        this.debugSymbolResolution = debug;
    }

    private final List<TraceCallParser> parsers = new ArrayList<>();

    // --- Call tracking ---
    public static class PendingCall {
        public String funcName;
        public long returnAddress;
        public boolean isJni;
        public long[] args;
        public String moduleName;
        public String funcAlias;

        public PendingCall(String moduleName, String funcName, long returnAddress, boolean isJni, long[] args) {
            this.moduleName = moduleName;
            this.funcName = funcName;
            this.returnAddress = returnAddress;
            this.isJni = isJni;
            this.args = args;
        }
    }
    private final Deque<PendingCall> pendingCalls = new ArrayDeque<>();
    private final Map<Long, String> jniIdMap = new HashMap<>();

    // LRU Cache for Symbol lookup
    private final Map<Long, SymbolInfo> symbolCache = new java.util.LinkedHashMap<Long, SymbolInfo>(1000, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, SymbolInfo> eldest) {
            return size() > 1000;
        }
    };

    // Hardware-style L1 Direct-Mapped Array Cache for VMP (8 Million slots, ~64MB RAM, covers 32MB physical addressing linearly)
    private final CachedInstruction[] l1Cache = new CachedInstruction[8388608];

    // L2 Fallback Cache for collisions (1 Million capacity)
    private final Map<Long, CachedInstruction> l2Cache = new java.util.LinkedHashMap<Long, CachedInstruction>(1000000, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, CachedInstruction> eldest) {
            return size() > 1000000;
        }
    };

    private static class CachedInstruction {
        final String mnemonic;
        final String opStr;
        final short[] regsRead;
        final short[] regWrite;
        final boolean isVectorLoadStore;
        final int baseReg;
        final long offset;
        final int manualMemDumpSize;
        final String manualMemDumpType;
        final boolean isCallOrSvc;
        final int machineCode;
        final Map<Short, Integer> unicornRegIdsRead = new HashMap<>();
        final Map<Short, String> regNamesRead = new HashMap<>();
        final Map<Short, Integer> unicornRegIdsWrite = new HashMap<>();
        final Map<Short, String> regNamesWrite = new HashMap<>();
        final long address;
        final String precomputedPrefix;

        CachedInstruction(Instruction ins, Emulator<?> emulator, int machineCode, long address) {
            this.address = address;
            this.machineCode = machineCode;
            this.mnemonic = ins.getMnemonic();
            this.opStr = ins.getOpStr();
            String lower = this.mnemonic != null ? this.mnemonic.toLowerCase(Locale.US) : "";
            this.isCallOrSvc = lower.equals("bl") || lower.equals("blr") || lower.equals("blx") || lower.equals("svc");

            StringBuilder pb = new StringBuilder();
            Module module = emulator.getMemory().findModuleByAddress(address);
            if (module != null) {
                pb.append('[').append(module.name).append("] ");
            } else {
                pb.append("[unknown] ");
            }
            pb.append("0x").append(Long.toHexString(address));
            if (module != null) {
                pb.append("!0x").append(Long.toHexString(address - module.base));
            }
            pb.append(' ').append(this.mnemonic).append(' ').append(this.opStr);
            this.precomputedPrefix = pb.toString();

            RegsAccess regsAccess = ins.regsAccess();
            if (regsAccess != null) {
                this.regsRead = regsAccess.getRegsRead();
                for (short r : regsRead) {
                    unicornRegIdsRead.put(r, ins.mapToUnicornReg(r));
                    regNamesRead.put(r, ins.regName(r));
                }

                short[] rawWrite = regsAccess.getRegsWrite();
                if (rawWrite.length > 0 && (mnemonic != null && (mnemonic.startsWith("st") || mnemonic.equals("push")))) {
                    int newLen = 0;
                    for (short r : rawWrite) {
                        String rn = ins.regName(r);
                        if (rn != null && !rn.startsWith("q") && !rn.startsWith("d") && !rn.startsWith("v")) newLen++;
                    }
                    short[] filtered = new short[newLen];
                    int idx = 0;
                    for (short r : rawWrite) {
                        String rn = ins.regName(r);
                        if (rn != null && !rn.startsWith("q") && !rn.startsWith("d") && !rn.startsWith("v")) filtered[idx++] = r;
                    }
                    this.regWrite = filtered;
                } else {
                    this.regWrite = rawWrite;
                }

                if (this.regWrite != null) {
                    for (short r : this.regWrite) {
                        unicornRegIdsWrite.put(r, ins.mapToUnicornReg(r));
                        regNamesWrite.put(r, ins.regName(r));
                    }
                }
            } else {
                this.regsRead = new short[0];
                this.regWrite = new short[0];
            }

            // Removed manual vector size calculation (relying on raw Unicorn hook `w 8` chunks)
            this.isVectorLoadStore = false;
            this.baseReg = -1;
            this.offset = 0;
            this.manualMemDumpSize = 0;
            this.manualMemDumpType = null;
        }
    }

    private final java.util.concurrent.LinkedBlockingQueue<String> logQueue = new java.util.concurrent.LinkedBlockingQueue<>(100000);
    private final Thread loggerThread;
    private static final String POISON_PILL = new String("POISON_PILL");

    private final StringBuilder asyncBlockBuffer = new StringBuilder(8388608); // 8MB装甲缓冲区
    private int linesInBlock = 0;

    private void checkFlushAsyncBlockBuffer() {
        if (this.linesInBlock > 50000) {
            try {
                logQueue.put(this.asyncBlockBuffer.toString());
            } catch (InterruptedException ignored) {}
            this.asyncBlockBuffer.setLength(0);
            this.linesInBlock = 0;
        }
    }

    private final PrintStream queueOut = new PrintStream(new java.io.OutputStream() {
        @Override
        public void write(int b) {}
    }, true) {
        @Override
        public void print(String s) {
            asyncBlockBuffer.append(s == null ? "null" : s);
        }
        @Override
        public void println(String s) {
            asyncBlockBuffer.append(s == null ? "null" : s).append('\n');
            linesInBlock++;
            checkFlushAsyncBlockBuffer();
        }
    };
    
    private final long startTime;
    private boolean traceStopped = false;

    public AssemblyCodeTextDumper(Emulator<?> emulator, long begin, long end, PrintStream redirect, TraceCodeListener listener) {
        this(emulator, begin, end, null, redirect, listener);
    }

    public AssemblyCodeTextDumper(Emulator<?> emulator, long begin, long end, String[] moduleNames, PrintStream redirect, TraceCodeListener listener) {
        this.startTime = System.currentTimeMillis();
        this.emulator = emulator;
        this.traceBegin = begin;
        this.traceEnd = end;
        this.traceModuleNames = moduleNames;
        if (moduleNames != null) {
            this.traceModules = new Module[moduleNames.length];
        } else {
            this.traceModules = null;
        }
        this.redirect = redirect;
        this.listener = listener;

        this.loggerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    while (true) {
                        String msg = logQueue.take();
                        if (POISON_PILL.equals(msg)) {
                            break;
                        }
                        PrintStream out = System.err;
                        if (AssemblyCodeTextDumper.this.redirect != null) {
                            out = AssemblyCodeTextDumper.this.redirect;
                        }
                        // log.info("这里使用的redirect: " + redirect.toString() + " 传入的redirect: " + AssemblyCodeTextDumper.this.redirect);
                        out.println(msg);
                    }
                    if (AssemblyCodeTextDumper.this.redirect != null && AssemblyCodeTextDumper.this.redirect != System.out && AssemblyCodeTextDumper.this.redirect != System.err) {
                        AssemblyCodeTextDumper.this.redirect.flush();
                        AssemblyCodeTextDumper.this.redirect.close();
                    }
                } catch (InterruptedException ignored) {}
            }
        });
        this.loggerThread.setName("Unidbg-Trace-Logger");
        this.loggerThread.setDaemon(true);
        this.loggerThread.start();

        // Register default parsers (can be overridden or appended)
        parsers.add(new DefaultSyscallParser());
        parsers.add(new DefaultJniParser());
        parsers.add(new DefaultLibcParser());
        parsers.add(new DefaultLibcppParser());
        
        try {
            emulator.getBackend().hook_add_new((ReadHook) this, begin, end, emulator);
            emulator.getBackend().hook_add_new((WriteHook) this, begin, end, emulator);
        } catch (Exception ignored) {}

        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                if (!traceStopped) {
                    stopTrace();
                }
            }
        }));
    }

    public void registerParser(TraceCallParser parser) {
        parsers.add(0, parser); // higher priority
    }

    @Override
    public void onAttach(UnHook unHook) {
        unHooks.add(unHook);
    }

    public void addUnHook(UnHook unHook) {
        unHooks.add(unHook);
    }

    @Override
    public void detach() {
        flush();
        for (UnHook unHook : unHooks) {
            unHook.unhook();
        }
        unHooks.clear();
    }

    @Override
    public synchronized void stopTrace() {
        if (traceStopped) return;
        traceStopped = true;
        
        detach();
        long elapsed = System.currentTimeMillis() - this.startTime;
        this.queueOut.println("=========================================================");
        this.queueOut.println("Trace Time total: " + elapsed + " ms");
        this.queueOut.println("=========================================================");
        
        System.err.println("\n=========================================================");
        System.err.println("Trace Time: " + elapsed + " ms (" + (redirect == null ? "Console" : "File") + ")");
        System.err.println("=========================================================");
        
        try {
            logQueue.put(POISON_PILL);
            loggerThread.join();
        } catch (InterruptedException ignored) {}
        IOUtils.close(redirect);
        redirect = null;
    }

    private boolean canTrace(long address) {
        if (traceModules != null) {
            for (int i = 0; i < traceModules.length; i++) {
                Module m = traceModules[i];
                if (m == null && traceModuleNames != null && traceModuleNames[i] != null) {
                    m = emulator.getMemory().findModule(traceModuleNames[i]);
                    if (m != null) {
                        traceModules[i] = m;
                    }
                }
                if (m != null && address >= m.base && address < m.base + m.size) return true;
            }
            return false;
        }
        return (traceBegin > traceEnd || (address >= traceBegin && address <= traceEnd));
    }

    @Override
    public void setRedirect(PrintStream redirect) {
        this.redirect = redirect;
    }

    private long manualMemDumpAddress = 0;
    private int manualMemDumpSize = 0;
    private String manualMemDumpType = "w";

    private void flush() {
        if (bufferedInstruction != null) {
            if (lastInstructionWritePrinter != null) {
                lastInstructionWritePrinter.print(emulator, emulator.getBackend(), bufferedInstruction, lastAddress);
            }

            if (!this.pendingMemoryDumps.isEmpty()) {
                bufferedInstruction.append(' ');
                for (int i = 0; i < pendingMemoryDumps.size(); i++) {
                    if (i > 0) bufferedInstruction.append(' ');
                    bufferedInstruction.append(pendingMemoryDumps.get(i));
                }
            }

            this.asyncBlockBuffer.append(bufferedInstruction).append('\n');
            this.linesInBlock++;

            if (this.pendingCallLine != null) {
                this.asyncBlockBuffer.append(this.pendingCallLine).append('\n');
                this.linesInBlock++;
                this.pendingCallLine = null;
            }
            
            if (this.manualMemDumpAddress != 0) {
                this.manualMemDumpAddress = 0;
                this.pendingMemoryDumps.clear();
            }

            bufferedInstruction = null;
            pendingMemoryDumps.clear();
            lastInstructionWritePrinter = null;
        }

        if (this.asyncBlockBuffer.length() > 0) {
            try {
                logQueue.put(this.asyncBlockBuffer.toString());
            } catch (InterruptedException ignored) {}
            this.asyncBlockBuffer.setLength(0);
            this.linesInBlock = 0;
        }
    }

    public boolean disableSMC = false;
    
    @Override
    public TraceHook setDisableSMC(boolean disableSMC) {
        this.disableSMC = disableSMC;
        return this;
    }

    public boolean disableHexdump = false;

    @Override
    public TraceHook setDisableHexdump(boolean disableHexdump) {
        this.disableHexdump = disableHexdump;
        return this;
    }

    public boolean disableFunctionCall = false;

    @Override
    public TraceHook setDisableFunctionCall(boolean disableFunctionCall) {
        this.disableFunctionCall = disableFunctionCall;
        return this;
    }

    private final StringBuilder globalInstructionBuffer = new StringBuilder(256);
    private long svcMemoryBase = -1;
    private long svcMemoryEnd = -1;

    @Override
    public void hook(Backend backend, long address, int size, Object user) {
        if (canTrace(address)) {
            try {
                // 1. Flush last instruction immediately
                StringBuilder instructionBuffer = this.bufferedInstruction;
                if (instructionBuffer != null) {
                    RegAccessPrinter lastPrinter = this.lastInstructionWritePrinter;
                    if (lastPrinter != null) {
                        Long lAddr = this.lastAddress;
                        lastPrinter.print(emulator, backend, instructionBuffer, lAddr != null ? lAddr : 0);
                    }

                    if (!this.pendingMemoryDumps.isEmpty()) {
                        instructionBuffer.append(' ');
                        for (int i = 0; i < pendingMemoryDumps.size(); i++) {
                            if (i > 0) instructionBuffer.append(' ');
                            instructionBuffer.append(pendingMemoryDumps.get(i));
                        }
                    }

                    this.asyncBlockBuffer.append(instructionBuffer).append('\n');
                    this.linesInBlock++;

                    if (this.pendingCallLine != null) {
                        this.asyncBlockBuffer.append(this.pendingCallLine).append('\n');
                        this.linesInBlock++;
                        this.pendingCallLine = null;
                    }

                    if (this.manualMemDumpAddress != 0) {
                        this.manualMemDumpAddress = 0;
                        this.pendingMemoryDumps.clear();
                    }

                    this.pendingMemoryDumps.clear();

                    checkFlushAsyncBlockBuffer();
                }

                // 2. Check if we just returned from a function to print the result EXACTLY before the NEXT instruction executes
                checkFunctionReturn(backend, address, emulator.is64Bit());

                // Filter out Unidbg internal SvcMemory tracing noise
                if (this.svcMemoryBase == -1) {
                    com.github.unidbg.memory.SvcMemory svcMemory = emulator.getSvcMemory();
                    if (svcMemory != null) {
                        this.svcMemoryBase = svcMemory.getBase();
                        this.svcMemoryEnd = svcMemory.getBase() + svcMemory.getSize();
                    } else {
                        this.svcMemoryBase = -2; // Not available
                    }
                }
                if (this.svcMemoryBase > 0 && address >= this.svcMemoryBase && address < this.svcMemoryEnd) {
                    this.pendingMemoryDumps.clear();
                    this.bufferedInstruction = null;
                    return; // Skip tracing framework SVC memory bounds
                }
                
                // PLT stub skip: skip fixed number of instructions after external call
                if (this.pltSkipCount > 0) {
                    this.pltSkipCount--;
                    this.pendingMemoryDumps.clear();
                    this.bufferedInstruction = null;
                    this.lastInstructionWritePrinter = null;
                    return;
                }
                
                // 3. Begin new instruction buffer
                this.pendingMemoryDumps.clear();
                this.globalInstructionBuffer.setLength(0);
                instructionBuffer = this.globalInstructionBuffer;
                this.bufferedInstruction = instructionBuffer;
                this.lastInstructionWritePrinter = null;
                this.currentInstructionAddress = address;
                this.lastAddress = address + size; // for RegAccessPrinter matching

                int machineCode = 0;
                
                int cacheSlot = (int) ((address / 4) & 8388607);
                CachedInstruction cachedIns = l1Cache[cacheSlot];
                if (cachedIns != null && cachedIns.address != address) {
                    cachedIns = l2Cache.get(address);
                }
                
                if (!disableSMC || cachedIns == null) {
                    try {
                        byte[] bytes = backend.mem_read(address, size);
                        if (bytes.length == 4) {
                            machineCode = (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8) | ((bytes[2] & 0xFF) << 16) | ((bytes[3] & 0xFF) << 24);
                        } else if (bytes.length == 2) {
                            machineCode = (bytes[0] & 0xFF) | ((bytes[1] & 0xFF) << 8);
                        }
                    } catch (Exception ignored) {}
                }

                Instruction insForRareFeatures = null;

                // Check SMC (Self-Modifying Code / Dynamic Decryption)
                if (!disableSMC && cachedIns != null && cachedIns.machineCode != machineCode) {
                    cachedIns = null; // Cache miss due to SMC! Code at address was actively changed.
                }

                if (cachedIns == null || listener != null || (!disableFunctionCall && cachedIns.isCallOrSvc)) {
                    Instruction[] insns = emulator.disassemble(address, size, 0);
                    if (insns == null || insns.length != 1) {
                        throw new IllegalStateException("insns=" + java.util.Arrays.toString(insns));
                    }
                    insForRareFeatures = insns[0];
                    if (cachedIns == null) {
                        cachedIns = new CachedInstruction(insForRareFeatures, emulator, machineCode, address);
                        CachedInstruction old = l1Cache[cacheSlot];
                        if (old != null && old.address != address) {
                            l2Cache.put(old.address, old); // evict to L2
                        }
                        l1Cache[cacheSlot] = cachedIns;
                        if (old != null && old.address == address) {
                             // replace directly
                        } else {
                            l2Cache.put(address, cachedIns);
                        }
                    }
                }
                
                instructionBuffer.append(cachedIns.precomputedPrefix);

                // 4. Semantic Parsing: Add C-style call inline
                if (!disableFunctionCall && cachedIns.isCallOrSvc && insForRareFeatures != null) {
                    handleCallAndSvcInstructions(insForRareFeatures, backend, emulator.is64Bit());
                }

                // --- Fix for Unicorn Engine's Vector Memory Hook Missing Bug ---
                if (!emulator.is32Bit() && cachedIns.isVectorLoadStore && cachedIns.baseReg != -1) {
                    long baseAddr = backend.reg_read(cachedIns.baseReg).longValue();
                    this.manualMemDumpAddress = baseAddr + cachedIns.offset;
                    this.manualMemDumpSize = cachedIns.manualMemDumpSize;
                    this.manualMemDumpType = cachedIns.manualMemDumpType;
                }
                // -------------------------------------------------------------

                // 5. Registers
                if (cachedIns.regsRead.length > 0) {
                    instructionBuffer.append(" ;");
                    RegAccessPrinter readPrinter = new RegAccessPrinter(address, cachedIns.regsRead, cachedIns.unicornRegIdsRead, cachedIns.regNamesRead, false, backend);
                    readPrinter.print(emulator, backend, instructionBuffer, address);
                }

                if (cachedIns.regWrite.length > 0) {
                    this.lastInstructionWritePrinter = new RegAccessPrinter(address + size, cachedIns.regWrite, cachedIns.unicornRegIdsWrite, cachedIns.regNamesWrite, true, backend);
                }

                if (listener != null && insForRareFeatures != null) {
                    listener.onInstruction(emulator, address, insForRareFeatures);
                }
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        } else {
            flush();
            // DO NOT clear pendingCalls here, as jumping out of bounds to libc modules means we want to retain the return addresses to catch when they return!
        }
    }

    private void checkFunctionReturn(Backend backend, long currentAddress, boolean is64Bit) {
        if (!pendingCalls.isEmpty() && pendingCalls.peek().returnAddress == currentAddress) {
            PendingCall call = pendingCalls.pop();
            
            long retVal = getArgRegValue(backend, 0, is64Bit);
            
            PrintStream out = queueOut;
            
            String formattedRet = null;
            TraceCallParser usedParser = null;
            for (TraceCallParser parser : parsers) {
                if (parser.canHandle(call.moduleName, call.funcName, call.isJni)) {
                    formattedRet = parser.formatReturnValue(call, retVal, backend, is64Bit, emulator, this);
                    usedParser = parser;
                    if (formattedRet != null) break;
                }
            }
            if (formattedRet == null) {
                formattedRet = "0x" + Long.toHexString(retVal);
            }
            
            out.println("ret " + formattedRet);
            
            if (usedParser != null) {
                usedParser.printPostReturnMemoryDump(out, call, retVal, backend, is64Bit, emulator, this);
            }
        }
    }

    private void handleCallAndSvcInstructions(Instruction ins, Backend backend, boolean is64Bit) {
        String mnem = ins.getMnemonic();
        if (mnem == null) return;
        String lowerMnem = mnem.toLowerCase(Locale.US);

        if (lowerMnem.equals("bl") || lowerMnem.equals("blr") || lowerMnem.equals("blx")) {
            long targetAddr = getCallTargetAddress(ins, backend, is64Bit);
            SymbolInfo symbol = resolveSymbol(targetAddr);
            
            // JNI dynamic resolution via backward instruction slicing
            if (symbol == null && (lowerMnem.equals("blr") || (lowerMnem.equals("blx") && !ins.getOpStr().startsWith("#")))) {
                com.github.unidbg.memory.SvcMemory svcMemory = emulator.getSvcMemory();
                if (svcMemory != null && targetAddr >= svcMemory.getBase() && targetAddr < svcMemory.getBase() + svcMemory.getSize()) {
                    String jumpReg = ins.getOpStr().trim(); // expected x8, r3, etc.
                    long offset = huntForJniOffset(jumpReg, ins.getAddress(), emulator, is64Bit);
                    if (offset != -1) {
                        int ptrSize = is64Bit ? 8 : 4;
                        int index = (int) (offset / ptrSize);
                        if (index >= 0 && index < DefaultJniParser.JNI_METHODS.length) {
                            symbol = new SymbolInfo();
                            symbol.moduleName = "JNIEnv";
                            symbol.funcName = DefaultJniParser.JNI_METHODS[index];
                            symbol.isJni = true;
                        }
                    }
                }
            }

            if (symbol != null) {
                // Tracking structure
                long returnAddr = ins.getAddress() + ins.getSize();
                returnAddr &= ~1L;
                long[] args = new long[4];
                for (int i=0; i<4; i++) args[i] = getArgRegValue(backend, i, is64Bit);
                PendingCall call = new PendingCall(symbol.moduleName, symbol.funcName, returnAddr, symbol.isJni, args);

                // Formatting C-style
                String callString = null;
                for (TraceCallParser parser : parsers) {
                    if (parser.canHandle(call.moduleName, call.funcName, call.isJni)) {
                        callString = parser.formatCall(call, backend, is64Bit, emulator, this);
                        if (callString != null) {
                            break;
                        }
                    }
                }
                if (callString == null) {
                    callString = (symbol.moduleName != null ? symbol.moduleName + " " : "") + symbol.funcName + "(X0=0x" + Long.toHexString(args[0]) + ", X1=0x" + Long.toHexString(args[1]) + ")";
                }
                
                call.funcAlias = callString;

                this.pendingCallLine = (call.isJni ? "call JNI " : "call ") + callString;
                if (symbol != null && symbol.moduleName != null && traceModuleNames != null) {
                    boolean isExternalCall = true;
                    for (String mn : traceModuleNames) {
                        if (mn != null && mn.equals(symbol.moduleName)) { isExternalCall = false; break; }
                    }
                    if (isExternalCall) {
                        this.pltSkipCount = is64Bit ? 4 : 2;
                    }
                }
                pendingCalls.push(call);
            }
        } else if (lowerMnem.equals("svc") && ins.getOpStr().contains("#0")) {
            long syscallNum = is64Bit ? backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X8).longValue()
                                      : backend.reg_read(unicorn.ArmConst.UC_ARM_REG_R7).longValue();
            
            long returnAddr = ins.getAddress() + ins.getSize();
            long[] args = new long[6];
            for (int i=0; i<6; i++) args[i] = getArgRegValue(backend, i, is64Bit);
            
            PendingCall call = new PendingCall("syscall", "syscall_" + syscallNum, returnAddr, false, args);
            // Re-assign name from maps is handled inside SyscallParser now via formatCall override, 
            // but SyscallParser matching uses the funcName properly.
            // Oh wait, SyscallParser can look up the true syscall name.
            
            String callString = null;
            for (TraceCallParser parser : parsers) {
                if (parser.canHandle("syscall", call.funcName, false)) {
                    callString = parser.formatCall(call, backend, is64Bit, emulator, this);
                    if (callString != null) {
                        break;
                    }
                }
            }
            if (callString == null) {
                callString = "svc syscall_" + syscallNum + " (X0=" + Long.toHexString(args[0]) + ")";
            }
            
            call.funcAlias = callString;
            
            this.pendingCallLine = "call " + callString;
            pendingCalls.push(call);
        }
    }

    // --- Argument / Return Helpers (Public for custom parsers) ---

    public Map<Long, String> getJniIdMap() {
        return jniIdMap;
    }

    public List<String> extractFormatSpecifiers(String format) {
        List<String> specs = new ArrayList<>();
        boolean inSpec = false;
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < format.length(); i++) {
            char c = format.charAt(i);
            if (inSpec) {
                current.append(c);
                if (Character.isLetter(c) || c == '%') {
                    if (c != '%') specs.add(current.toString());
                    inSpec = false;
                    current.setLength(0);
                }
            } else if (c == '%') {
                inSpec = true;
                current.append(c); // Add '%'
            }
        }
        return specs;
    }

    public String formatArgValue(String type, long val, Backend backend) {
        if ("str".equals(type)) {
            String s = readStringSafe(backend, val);
            return s != null ? "\"" + escapeString(s) + "\"" : "0x" + Long.toHexString(val);
        } else if ("ptr".equals(type) || "buf".equals(type)) {
            if (val == 0) return "NULL";
            return "0x" + Long.toHexString(val);
        } else if ("jobject".equals(type)) {
            if (val == 0) return "NULL";
            return formatJobjectValue(val);
        } else if ("jmethodID".equals(type) || "jclass".equals(type) || "jfieldID".equals(type)) {
            String known = jniIdMap.get(val);
            if (known != null) {
                return String.format("0x%x (%s)", val, known);
            }
            return "0x" + Long.toHexString(val);
        } else if ("char".equals(type)) {
            long c = val & 0xFF;
            if (c >= 32 && c <= 126) {
                return String.format("%d ('%c')", val, (char)c);
            } else if (c == '\n') return val + " ('\\n')";
            else if (c == '\r') return val + " ('\\r')";
            else if (c == '\t') return val + " ('\\t')";
            else if (c == 0) return val + " ('\\0')";
            return String.valueOf(val);
        } else if ("int".equals(type) || "size".equals(type)) {
            return "0x" + Long.toHexString(val);
        }
        return "0x" + Long.toHexString(val);
    }

    public String formatJobjectValue(long val) {
        try {
            Object vm = emulator.get("com.github.unidbg.linux.android.dvm.VM");
            if (vm != null) {
                java.lang.reflect.Method getObject = vm.getClass().getMethod("getObject", int.class);
                Object dvmObj = getObject.invoke(vm, (int) val);
                if (dvmObj != null) {
                    return dvmObj.toString();
                }
            }
        } catch (Exception ignored) {
        }
        return "0x" + Long.toHexString(val);
    }



    // --- Hardware Memory Hooks ---

    public void onMemoryRead(Backend backend, long address, int size) {
        if (disableHexdump) return;
        if (bufferedInstruction != null) {
            long pc = backend.reg_read(emulator.is32Bit() ? unicorn.ArmConst.UC_ARM_REG_PC : unicorn.Arm64Const.UC_ARM64_REG_PC).longValue();
            Long currentAddr = currentInstructionAddress;
            if (currentAddr != null && Math.abs(pc - currentAddr) > 8) {
                return;
            }
            pendingMemoryDumps.add("mem_r=0x" + Long.toHexString(address));
        }
    }

    public void onMemoryWrite(Backend backend, long address, int size, long value) {
        if (disableHexdump) return;
        if (bufferedInstruction != null) {
            long pc = backend.reg_read(emulator.is32Bit() ? unicorn.ArmConst.UC_ARM_REG_PC : unicorn.Arm64Const.UC_ARM64_REG_PC).longValue();
            Long currentAddr = currentInstructionAddress;
            if (currentAddr != null && Math.abs(pc - currentAddr) > 8) {
                return;
            }
            pendingMemoryDumps.add("mem_w=0x" + Long.toHexString(address));
        }
    }

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    
    public String formatMemDump(String type, long address, byte[] data) {
        StringBuilder sb = new StringBuilder();
        int len = data.length;
        
        for (int offset = 0; offset < len; offset += 16) {
            if (offset > 0) sb.append("\n");
            
            int lineLen = Math.min(16, len - offset);
            sb.append('(').append(type).append(' ').append(lineLen).append(") ");
            
            String addrHex = Long.toHexString(address + offset);
            sb.append("0x").append(addrHex);
            for (int i=addrHex.length(); i<10; i++) sb.append(' '); // Align
            
            for (int i = 0; i < 16; i++) {
                if (i < lineLen) {
                    int v = data[offset + i] & 0xFF;
                    sb.append(HEX_ARRAY[v >>> 4]).append(HEX_ARRAY[v & 0x0F]).append(' ');
                } else {
                    sb.append("   ");
                }
            }
            sb.append(" |");
            for (int i = 0; i < lineLen; i++) {
                byte b = data[offset + i];
                if (b >= 0x20 && b <= 0x7e) {
                    sb.append((char) b);
                } else {
                    sb.append('.');
                }
            }
            sb.append('|');
            
            // Append the integer interpretation
            if (lineLen == 1 || lineLen == 2 || lineLen == 4 || lineLen == 8) {
                sb.append(" [0x");
                for (int i = lineLen - 1; i >= 0; i--) {
                    int v = data[offset + i] & 0xFF;
                    sb.append(HEX_ARRAY[v >>> 4]).append(HEX_ARRAY[v & 0x0F]);
                }
                sb.append(']');
            } else if (lineLen >= 8) { 
                sb.append(" [0x");
                for (int i = 7; i >= 0; i--) {
                    int v = data[offset + i] & 0xFF;
                    sb.append(HEX_ARRAY[v >>> 4]).append(HEX_ARRAY[v & 0x0F]);
                }
                sb.append(']');
            }
        }
        
        return sb.toString();
    }

    // --- Helpers ---
    private long getCallTargetAddress(Instruction ins, Backend backend, boolean is64Bit) {
        String opStr = ins.getOpStr();
        String mnemonic = ins.getMnemonic().toLowerCase(Locale.US);

        if (mnemonic.equals("blr") || (mnemonic.equals("blx") && !opStr.startsWith("#"))) {
            int regId = getRegisterId(opStr.trim(), is64Bit);
            if (regId != -1) {
                long val = backend.reg_read(regId).longValue();
                // If Thumb mode, mask out the LSB thumb indicator
                return is64Bit ? val : (val & ~1L);
            }
            return 0;
        }

        if (opStr.startsWith("#")) {
            return parseImm(opStr.substring(1));
        }

        try {
            return Long.parseLong(opStr.replace("0x", ""), 16);
        } catch (NumberFormatException e) {
            return backend.reg_read(is64Bit ? unicorn.Arm64Const.UC_ARM64_REG_PC : unicorn.ArmConst.UC_ARM_REG_PC).longValue();
        }
    }

    private long huntForJniOffset(String jumpReg, long blrAddress, Emulator<?> emulator, boolean is64Bit) {
        try {
            int lookback = 24; // Look back up to 24 bytes (6 instructions)
            long startAddr = Math.max(0, blrAddress - lookback);
            Instruction[] insns = emulator.disassemble(startAddr, (int)(blrAddress - startAddr), 0);
            if (insns == null) return -1;
            
            // Iterate backwards
            for (int i = insns.length - 1; i >= 0; i--) {
                Instruction preIns = insns[i];
                if (preIns.getMnemonic() != null && preIns.getMnemonic().startsWith("ldr")) {
                    String opStr = preIns.getOpStr();
                    if (opStr != null && opStr.startsWith(jumpReg + ",")) {
                        int hashIdx = opStr.indexOf('#');
                        int bracketIdx = opStr.indexOf(']');
                        if (hashIdx != -1 && bracketIdx != -1 && hashIdx < bracketIdx) {
                            String offsetStr = opStr.substring(hashIdx + 1, bracketIdx).trim();
                            return parseImm(offsetStr);
                        } else if (opStr.contains("[") && !opStr.contains("#")) {
                            // ldr x8, [x0] means offset 0!
                            return 0;
                        }
                    }
                }
            }
        } catch (Exception ignored) {}
        return -1;
    }

    private int getRegisterId(String regName, boolean is64Bit) {
        regName = regName.toLowerCase();
        if (regName.equals("sp")) return is64Bit ? unicorn.Arm64Const.UC_ARM64_REG_SP : unicorn.ArmConst.UC_ARM_REG_SP;
        if (regName.equals("fp") || regName.equals("x29")) return is64Bit ? unicorn.Arm64Const.UC_ARM64_REG_X29 : unicorn.ArmConst.UC_ARM_REG_FP;
        if (regName.equals("pc")) return is64Bit ? unicorn.Arm64Const.UC_ARM64_REG_PC : unicorn.ArmConst.UC_ARM_REG_PC;
        if (regName.equals("lr") || regName.equals("x30")) return is64Bit ? unicorn.Arm64Const.UC_ARM64_REG_X30 : unicorn.ArmConst.UC_ARM_REG_LR;
        
        boolean isW = regName.startsWith("w");
        if (regName.startsWith("x") || regName.startsWith("w") || regName.startsWith("r")) {
            int regNum = Integer.parseInt(regName.substring(1));
            if (is64Bit) {
                return isW ? (unicorn.Arm64Const.UC_ARM64_REG_W0 + regNum) : (unicorn.Arm64Const.UC_ARM64_REG_X0 + regNum);
            } else {
                return unicorn.ArmConst.UC_ARM_REG_R0 + regNum;
            }
        }
        return -1;
    }

    private static long parseImm(String immStr) {
        immStr = immStr.trim();
        if (immStr.startsWith("0x") || immStr.startsWith("0X")) return Long.parseLong(immStr.substring(2), 16);
        if (immStr.startsWith("-0x") || immStr.startsWith("-0X")) return -Long.parseLong(immStr.substring(3), 16);
        return Long.parseLong(immStr);
    }

    private SymbolInfo resolveSymbol(long address) {
        if (symbolCache.containsKey(address)) {
            return symbolCache.get(address); // Can be null if previously resolved as null
        }
        SymbolInfo info = doResolveSymbol(address);
        symbolCache.put(address, info);
        return info;
    }

    private SymbolInfo doResolveSymbol(long address) {
        try {
            SymbolInfo svcSymbol = resolveSvcSymbol(address);
            if (svcSymbol != null) {
                if (debugSymbolResolution) {
                    log.info("[TraceDebug] 0x" + Long.toHexString(address) + " resolved via SvcMemory hook -> " + svcSymbol.moduleName + "::" + svcSymbol.funcName);
                }
                return svcSymbol;
            }

            com.github.unidbg.memory.Memory memory = emulator.getMemory();
            Module module = memory.findModuleByAddress(address);
            if (module == null) {
                if (debugSymbolResolution) log.info("[TraceDebug] 0x" + Long.toHexString(address) + " -> Not in any mapped module (Null)");
                return null;
            }

            long offset = address - module.base;

            SymbolInfo pltSymbol = resolvePltStub(address, module, memory);
            if (pltSymbol != null) {
                if (debugSymbolResolution) {
                    log.info("[TraceDebug] 0x" + Long.toHexString(address) + " resolved via PLT Parser -> " + pltSymbol.moduleName + "::" + pltSymbol.funcName);
                }
                return pltSymbol;
            }

            Symbol symbol = module.findClosestSymbolByAddress(address, false);
            if (symbol != null && Math.abs(address - symbol.getAddress()) <= SYMBOL_MAX_OFFSET) {
                String symbolName = symbol.getName();
                boolean isStart = "start".equals(symbolName) || "_start".equals(symbolName);
                if (!isStart || address == symbol.getAddress()) {
                    SymbolInfo info = new SymbolInfo();
                    info.moduleName = module.name;
                    
                    if (symbolName != null && (symbolName.contains("JNI") || symbolName.startsWith("_ZN3art3JNI") || module.name.equals("libart.so"))) {
                        info.isJni = true;
                        info.funcName = extractJniFunctionName(symbolName);
                    } else {
                        info.isJni = false;
                        info.funcName = symbolName;
                    }
                    if (debugSymbolResolution) {
                        log.info("[TraceDebug] 0x" + Long.toHexString(address) + " resolved via internal Symbol Table -> " + info.moduleName + "::" + info.funcName);
                    }
                    return info;
                }
            }
            
            // Fallback to IDA-style sub_[offset] for stripped internal calls
            SymbolInfo info = new SymbolInfo();
            info.moduleName = module.name;
            long subOffset = address - module.base;
            info.funcName = "sub_" + Long.toHexString(subOffset);
            info.isJni = false;
            // Omit printing the fallback in debug mode to avoid severe console spam on heavy loops, 
            // unless we strictly need it. But sub_ logs themselves will be printed as calls by the tracer naturally.
            return info;
            
        } catch (Exception ignored) {
        }
        return null;
    }

    private SymbolInfo resolvePltStub(long pltAddr, Module pltModule, com.github.unidbg.memory.Memory memory) {
        try {
            Backend backend = emulator.getBackend();
            boolean is64Bit = emulator.is64Bit();

            long offset = pltAddr - pltModule.base;
            if (offset < 0 || offset > 0x800000) return null; // 8MB PLT range

            int stubSize = is64Bit ? 16 : 12;
            byte[] stubCode = backend.mem_read(pltAddr, stubSize);
            if (stubCode == null) return null;

            long gotAddr = parsePltStubGotAddress(pltAddr, stubCode, is64Bit);
            if (gotAddr == 0) return null;

            int ptrSize = is64Bit ? 8 : 4;
            byte[] gotEntry = backend.mem_read(gotAddr, ptrSize);
            if (gotEntry == null) return null;

            long funcAddr = 0;
            for (int i = ptrSize - 1; i >= 0; i--) {
                funcAddr = (funcAddr << 8) | (gotEntry[i] & 0xFFL);
            }

            Module funcModule = memory.findModuleByAddress(funcAddr);
            SymbolInfo info = new SymbolInfo();

            if (funcModule == null) {
                SymbolInfo svcInfo = resolveSvcSymbol(funcAddr);
                if (svcInfo != null) {
                    return svcInfo;
                }
                return null;
            }

            // Strict validation: If the GOT points to the SAME module, it's very likely an unresolved lazy-binding PLT0 stub.
            // We must enforce strict matching so we don't accidentally match the PLT0 stub to the closest exported symbol (like 'start').
            boolean isSameModule = (funcModule == pltModule);

            Symbol funcSymbol = funcModule.findClosestSymbolByAddress(funcAddr, false);
            if (funcSymbol == null) return null;
            
            if (isSameModule) {
                if (Math.abs(funcAddr - funcSymbol.getAddress()) > 4) return null;
            } else {
                if (Math.abs(funcAddr - funcSymbol.getAddress()) > SYMBOL_MAX_OFFSET) return null;
            }

            String symbolName = funcSymbol.getName();
            if (symbolName == null || symbolName.equals("start") || symbolName.equals("_start") || symbolName.isEmpty()) return null;

            info.moduleName = funcModule.name;
            if (isJniSymbolCheck(symbolName, funcModule.name)) {
                info.isJni = true;
                info.funcName = extractJniFunctionName(symbolName);
            } else {
                info.isJni = false;
                info.funcName = symbolName;
            }
            return info;
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isJniSymbolCheck(String symbolName, String moduleName) {
        return symbolName.contains("JNI") || symbolName.startsWith("_ZN3art3JNI") || "libart.so".equals(moduleName) || "libnativehelper.so".equals(moduleName);
    }

    private long parsePltStubGotAddress(long pltAddr, byte[] stubCode, boolean is64Bit) {
        if (is64Bit) {
            if (stubCode.length < 8) return 0;

            int inst0 = readLittleEndianInt(stubCode, 0);
            int inst1 = readLittleEndianInt(stubCode, 4);

            if ((inst0 & 0x9F000000) != 0x90000000) return 0;

            long immlo = (inst0 >> 29) & 0x3;
            long immhi = (inst0 >> 5) & 0x7FFFF;
            long imm21 = (immhi << 2) | immlo;

            if ((imm21 & 0x100000) != 0) {
                imm21 |= 0xFFFFFFFFFFE00000L;
            }

            long pageBase = (pltAddr & ~0xFFFL) + (imm21 << 12);

            if ((inst1 & 0xFFC00000) == 0xF9400000) {
                int imm12 = (inst1 >> 10) & 0xFFF;
                return pageBase + (imm12 << 3);
            }

            if ((inst1 & 0xFFC00000) == 0xB9400000) {
                int imm12 = (inst1 >> 10) & 0xFFF;
                return pageBase + (imm12 << 2);
            }

            if (stubCode.length >= 12 && (inst1 & 0xFFC00000) == 0x91000000) {
                int addImm = (inst1 >> 10) & 0xFFF;
                int shift = ((inst1 >> 22) & 0x3) == 1 ? 12 : 0;
                pageBase += (long) addImm << shift;

                int inst2 = readLittleEndianInt(stubCode, 8);
                if ((inst2 & 0xFFC00000) == 0xF9400000) {
                    int imm12 = (inst2 >> 10) & 0xFFF;
                    return pageBase + (imm12 << 3);
                }
            }
            return 0;
        } else {
            try {
                boolean isThumb = (pltAddr & 1) != 0;
                long realAddr = pltAddr & ~1L;
                byte[] stubCodeArm32 = emulator.getBackend().mem_read(realAddr, 16);
                
                // Hardware pattern match for fastest BFD parsing (add PC + add r12 + ldr PC)
                int inst0 = readLittleEndianInt(stubCodeArm32, 0);
                int inst1 = readLittleEndianInt(stubCodeArm32, 4);
                int inst2 = readLittleEndianInt(stubCodeArm32, 8);
                if (!isThumb && (inst0 & 0xFFFFF000) == 0xE28FC000 && (inst1 & 0xFFFFF000) == 0xE28CC000 && (inst2 & 0xFFFFF000) == 0xE5BCF000) {
                    long ip = realAddr + 8;
                    ip += Integer.rotateRight(inst0 & 0xFF, ((inst0 >> 8) & 0xF) * 2);
                    ip += Integer.rotateRight(inst1 & 0xFF, ((inst1 >> 8) & 0xF) * 2);
                    ip += (inst2 & 0xFFF);
                    return ip;
                }

                // Fallback to Capstone evaluation
                int mode = isThumb ? capstone.Capstone.CS_MODE_THUMB : capstone.Capstone.CS_MODE_ARM;
                capstone.Capstone cs = new capstone.Capstone(capstone.Capstone.CS_ARCH_ARM, mode);
                Instruction[] insns = cs.disasm(stubCodeArm32, realAddr);
                
                if (insns != null && insns.length >= 2) {
                    long r12 = 0;
                    boolean r12Initialized = false;
                    for (Instruction ins : insns) {
                        String mnem = ins.getMnemonic().toLowerCase();
                        String opStr = ins.getOpStr().toLowerCase().replace(" ", "");
                        long instPc = ins.getAddress() + (isThumb ? 4 : 8);
                        
                        try {
                            if (mnem.startsWith("add") && (opStr.contains(",pc,") || opStr.contains(",r15,")) && opStr.contains("#")) {
                                String imm = opStr.substring(opStr.indexOf('#') + 1).split(",")[0].split("\\]")[0];
                                r12 = instPc + parseImm(imm);
                                r12Initialized = true;
                            } else if (mnem.startsWith("add") && (opStr.contains("r12,r12,") || opStr.contains("ip,ip,")) && opStr.contains("#")) {
                                String imm = opStr.substring(opStr.indexOf('#') + 1).split(",")[0].split("\\]")[0];
                                if (!r12Initialized) r12 = instPc;
                                r12 += parseImm(imm);
                                r12Initialized = true;
                            } else if (mnem.startsWith("ldr") && opStr.contains("pc,[")) {
                                if (opStr.contains("#")) {
                                    int hashIdx = opStr.indexOf('#');
                                    int bracketIdx = opStr.indexOf(']');
                                    if (hashIdx != -1 && bracketIdx != -1) {
                                        return (r12Initialized ? r12 : instPc) + parseImm(opStr.substring(hashIdx + 1, bracketIdx));
                                    }
                                } else {
                                    return r12Initialized ? r12 : instPc;
                                }
                            }
                        } catch (Exception ignored) { }
                    }
                }
                cs.close();
                
            } catch (Exception ignored) {}
            return 0;
        }
    }

    private int readLittleEndianInt(byte[] data, int offset) {
         return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8) | ((data[offset + 2] & 0xFF) << 16) | ((data[offset + 3] & 0xFF) << 24);
    }

    private SymbolInfo resolveSvcSymbol(long address) {
        try {
            com.github.unidbg.memory.SvcMemory svcMemory = emulator.getSvcMemory();
            if (address >= svcMemory.getBase() && address < svcMemory.getBase() + svcMemory.getSize()) {
                com.github.unidbg.memory.MemRegion region = svcMemory.findRegion(address);
                if (region != null && region.getName() != null && !region.getName().contains("Svc")) {
                    SymbolInfo info = new SymbolInfo();
                    String name = region.getName();
                    info.funcName = name;
                    
                    char firstChar = name.charAt(0);
                    if (firstChar == '_') {
                        firstChar = name.length() > 1 ? name.charAt(1) : firstChar;
                    }
                    info.isJni = Character.isUpperCase(firstChar);
                    info.moduleName = info.isJni ? "JNIEnv" : "libc.so";
                    return info;
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private String extractJniFunctionName(String symbolName) {
        String[] jniFuncs = { "FindClass", "GetMethodID", "GetStaticMethodID", "GetFieldID",
                "GetStaticFieldID", "NewStringUTF", "GetStringUTFChars", "ReleaseStringUTFChars",
                "GetStringUTFLength", "NewByteArray", "GetByteArrayElements", "ReleaseByteArrayElements",
                "GetArrayLength", "SetByteArrayRegion", "GetByteArrayRegion", "CallObjectMethod",
                "CallVoidMethod", "CallIntMethod", "CallBooleanMethod", "CallStaticObjectMethod",
                "CallStaticVoidMethod", "CallStaticIntMethod", "GetObjectField", "SetObjectField",
                "GetIntField", "SetIntField", "RegisterNatives", "DeleteLocalRef", "NewGlobalRef",
                "DeleteGlobalRef", "ExceptionCheck", "ExceptionClear" };
        for (String f : jniFuncs) {
            if (symbolName.contains(f)) return f;
        }
        return symbolName;
    }

    public long getArgRegValue(Backend backend, int argIndex, boolean is64Bit) {
        if (is64Bit) {
            if (argIndex < 8) return backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0 + argIndex).longValue(); // X0-X7
            long sp = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_SP).longValue();
            return readWord(backend, sp + (argIndex - 8) * 8L, true);
        } else {
            if (argIndex < 4) return backend.reg_read(unicorn.ArmConst.UC_ARM_REG_R0 + argIndex).longValue(); // R0-R3
            long sp = backend.reg_read(unicorn.ArmConst.UC_ARM_REG_SP).longValue();
            return readWord(backend, sp + (argIndex - 4) * 4L, false);
        }
    }

    public long readWord(Backend backend, long address, boolean is64Bit) {
        try {
            byte[] data = backend.mem_read(address, is64Bit ? 8 : 4);
            long val = 0;
            for (int i = data.length - 1; i >= 0; i--) {
                val = (val << 8) | (data[i] & 0xFFL);
            }
            return val;
        } catch (Exception e) {
            return 0;
        }
    }

    public String readStringSafe(Backend backend, long address) {
        if (address == 0) return null;
        try {
            byte[] data = backend.mem_read(address, 512);
            if (data == null || data.length == 0) return null;
            int len = 0, printable = 0;
            for (int i = 0; i < data.length; i++) {
                if (data[i] == 0) { len = i; break; }
                if (data[i] >= 0x20 && data[i] < 0x7f) printable++;
            }
            if (len >= 2 && printable * 100 / len >= 70) {
                return new String(data, 0, len);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    public String escapeString(String s) {
        if (s == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '"') sb.append("\\\"");
            else if (c == '\\') sb.append("\\\\");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c == '\t') sb.append("\\t");
            else if (c < 32 || c > 126) sb.append(String.format("\\x%02x", (int)c));
            else sb.append(c);
        }
        return sb.toString();
    }

    private static class SymbolInfo {
        String moduleName;
        String funcName;
        boolean isJni;
    }



    public static AssemblyCodeTextDumper addHook(Emulator<?> emulator, long begin, long end, java.io.PrintStream redirect, TraceCodeListener listener) {
        final AssemblyCodeTextDumper hook = new AssemblyCodeTextDumper(emulator, begin, end, redirect, listener);
        emulator.getBackend().hook_add_new((CodeHook) hook, begin, end, emulator);
        
        emulator.getBackend().hook_add_new(new ReadHook() {
            @Override public void onAttach(UnHook unHook) { hook.addUnHook(unHook); }
            @Override public void detach() {}
            @Override public void hook(Backend backend, long address, int size, Object user) {
                hook.onMemoryRead(backend, address, size);
            }
        }, 1, 0, emulator);

        emulator.getBackend().hook_add_new(new WriteHook() {
            @Override public void onAttach(UnHook unHook) { hook.addUnHook(unHook); }
            @Override public void detach() {}
            @Override public void hook(Backend backend, long address, int size, long value, Object user) {
                hook.onMemoryWrite(backend, address, size, value);
            }
        }, 1, 0, emulator);

        return hook;
    }
}
