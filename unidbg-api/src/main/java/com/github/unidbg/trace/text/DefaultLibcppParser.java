package com.github.unidbg.trace.text;

import com.github.unidbg.*;
import com.github.unidbg.arm.backend.Backend;
import java.io.PrintStream;

public class DefaultLibcppParser implements TraceCallParser {

    @Override
    public boolean canHandle(String moduleName, String symbolName, boolean isJni) {
        if (isJni) return false;
        if ("libc++.so".equals(moduleName) || "libstdc++.so".equals(moduleName)) return true;
        if (symbolName != null && (symbolName.startsWith("_Zn") || symbolName.startsWith("_Zd"))) return true;
        return false;
    }

    @Override
    public String formatCall(AssemblyCodeTextDumper.PendingCall call, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        String funcName = call.funcName;
        if (funcName == null) return null;
        
        long arg0 = dumper.getArgRegValue(backend, 0, is64Bit);
        
        if (funcName.startsWith("_Znwj") || funcName.startsWith("_Znwm")) { 
            return "libc++ operator new(" + arg0 + ")";
        } else if (funcName.startsWith("_Znaj") || funcName.startsWith("_Znam")) { 
            return "libc++ operator new[](" + arg0 + ")";
        } else if (funcName.startsWith("_ZdlPv")) { 
            return "libc++ operator delete(0x" + Long.toHexString(arg0) + ")";
        } else if (funcName.startsWith("_ZdaPv")) { 
            return "libc++ operator delete[](0x" + Long.toHexString(arg0) + ")";
        }
        
        return null;
    }

    @Override
    public String formatReturnValue(AssemblyCodeTextDumper.PendingCall call, long retVal, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        String funcName = call.funcName;
        if (funcName != null && funcName.startsWith("_Zn")) {
            return "0x" + Long.toHexString(retVal);
        }
        return null; // fallback
    }

    @Override
    public void printPostReturnMemoryDump(PrintStream out, AssemblyCodeTextDumper.PendingCall call, long retVal, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
    }
}
