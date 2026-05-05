package com.github.unidbg.trace.text;

import com.github.unidbg.*;
import com.github.unidbg.arm.backend.Backend;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DefaultLibcParser implements TraceCallParser {

    private final Map<String, String[]> libcFuncs = new HashMap<>();

    public DefaultLibcParser() {
        // Memory Block
        libcFuncs.put("malloc", new String[]{"size:size"});
        libcFuncs.put("calloc", new String[]{"nmemb:size", "size:size"});
        libcFuncs.put("realloc", new String[]{"ptr:ptr", "size:size"});
        libcFuncs.put("free", new String[]{"ptr:ptr"});
        libcFuncs.put("memcpy", new String[]{"dest:ptr", "src:ptr", "n:size"});
        libcFuncs.put("memmove", new String[]{"dest:ptr", "src:ptr", "n:size"});
        libcFuncs.put("memset", new String[]{"s:ptr", "c:int", "n:size"});
        libcFuncs.put("memcmp", new String[]{"s1:str", "s2:str", "n:size"});
        libcFuncs.put("memchr", new String[]{"s:ptr", "c:char", "n:size"});
        libcFuncs.put("bzero", new String[]{"s:ptr", "n:size"});
        // String Block
        libcFuncs.put("strcpy", new String[]{"dest:ptr", "src:str"});
        libcFuncs.put("strncpy", new String[]{"dest:ptr", "src:str", "n:size"});
        libcFuncs.put("strcat", new String[]{"dest:str", "src:str"});
        libcFuncs.put("strncat", new String[]{"dest:str", "src:str", "n:size"});
        libcFuncs.put("strcmp", new String[]{"s1:str", "s2:str"});
        libcFuncs.put("strncmp", new String[]{"s1:str", "s2:str", "n:size"});
        libcFuncs.put("strchr", new String[]{"s:str", "c:char"});
        libcFuncs.put("strrchr", new String[]{"s:str", "c:char"});
        libcFuncs.put("strstr", new String[]{"haystack:str", "needle:str"});
        libcFuncs.put("strlen", new String[]{"s:str"});
        libcFuncs.put("strnlen", new String[]{"s:str", "maxlen:size"});
        libcFuncs.put("strspn", new String[]{"s:str", "accept:str"});
        libcFuncs.put("strcspn", new String[]{"s:str", "reject:str"});
        libcFuncs.put("strpbrk", new String[]{"s:str", "accept:str"});
        libcFuncs.put("strtok", new String[]{"s:str", "delim:str"});
        libcFuncs.put("strtok_r", new String[]{"s:str", "delim:str", "saveptr:ptr"});
        libcFuncs.put("strdup", new String[]{"s:str"});
        libcFuncs.put("strndup", new String[]{"s:str", "n:size"});
        libcFuncs.put("strerror", new String[]{"errnum:int"});
        libcFuncs.put("toupper", new String[]{"c:char"});
        libcFuncs.put("tolower", new String[]{"c:char"});
        // IO / System Block
        libcFuncs.put("sprintf", new String[]{"str:ptr", "format:str"});
        libcFuncs.put("snprintf", new String[]{"str:ptr", "size:size", "format:str"});
        libcFuncs.put("vsprintf", new String[]{"str:ptr", "format:str", "ap:ptr"});
        libcFuncs.put("vsnprintf", new String[]{"str:ptr", "size:size", "format:str", "ap:ptr"});
        libcFuncs.put("sscanf", new String[]{"str:str", "format:str"});
        libcFuncs.put("vsscanf", new String[]{"str:str", "format:str", "ap:ptr"});
        libcFuncs.put("printf", new String[]{"format:str"});
        libcFuncs.put("fprintf", new String[]{"stream:ptr", "format:str"});
        libcFuncs.put("puts", new String[]{"s:str"});
        libcFuncs.put("fputs", new String[]{"s:str", "stream:ptr"});
        libcFuncs.put("putchar", new String[]{"c:char"});
        libcFuncs.put("fopen", new String[]{"pathname:str", "mode:str"});
        libcFuncs.put("fdopen", new String[]{"fd:int", "mode:str"});
        libcFuncs.put("fclose", new String[]{"stream:ptr"});
        libcFuncs.put("fread", new String[]{"ptr:ptr", "size:size", "nmemb:size", "stream:ptr"});
        libcFuncs.put("fwrite", new String[]{"ptr:ptr", "size:size", "nmemb:size", "stream:ptr"});
        libcFuncs.put("fseek", new String[]{"stream:ptr", "offset:int", "whence:int"});
        libcFuncs.put("ftell", new String[]{"stream:ptr"});
        libcFuncs.put("rewind", new String[]{"stream:ptr"});
        libcFuncs.put("fflush", new String[]{"stream:ptr"});
        libcFuncs.put("open", new String[]{"pathname:str", "flags:int", "mode:int"});
        libcFuncs.put("close", new String[]{"fd:int"});
        libcFuncs.put("read", new String[]{"fd:int", "buf:ptr", "count:size"});
        libcFuncs.put("write", new String[]{"fd:int", "buf:ptr", "count:size"});
        libcFuncs.put("lseek", new String[]{"fd:int", "offset:size", "whence:int"});
        libcFuncs.put("pread", new String[]{"fd:int", "buf:ptr", "count:size", "offset:size"});
        libcFuncs.put("pwrite", new String[]{"fd:int", "buf:ptr", "count:size", "offset:size"});
        libcFuncs.put("access", new String[]{"pathname:str", "mode:int"});
        libcFuncs.put("unlink", new String[]{"pathname:str"});
        libcFuncs.put("remove", new String[]{"pathname:str"});
        libcFuncs.put("rename", new String[]{"oldpath:str", "newpath:str"});
        libcFuncs.put("mkdir", new String[]{"pathname:str", "mode:int"});
        libcFuncs.put("rmdir", new String[]{"pathname:str"});
        libcFuncs.put("chmod", new String[]{"pathname:str", "mode:int"});
        libcFuncs.put("chown", new String[]{"pathname:str", "owner:int", "group:int"});
        libcFuncs.put("exit", new String[]{"status:int"});
        libcFuncs.put("abort", new String[]{});
        libcFuncs.put("sleep", new String[]{"seconds:int"});
        libcFuncs.put("usleep", new String[]{"usec:int"});
        // Environment / Android Specific
        libcFuncs.put("getenv", new String[]{"name:str"});
        libcFuncs.put("setenv", new String[]{"name:str", "value:str", "overwrite:int"});
        libcFuncs.put("putenv", new String[]{"string:str"});
        libcFuncs.put("unsetenv", new String[]{"name:str"});
        libcFuncs.put("system", new String[]{"command:str"});
        libcFuncs.put("__system_property_get", new String[]{"name:str", "value:ptr"});
        libcFuncs.put("dlopen", new String[]{"filename:str", "flags:int"});
        libcFuncs.put("dlsym", new String[]{"handle:ptr", "symbol:str"});
        libcFuncs.put("dlclose", new String[]{"handle:ptr"});
        libcFuncs.put("dlerror", new String[]{});
        // Mutex / Threads
        libcFuncs.put("pthread_create", new String[]{"thread:ptr", "attr:ptr", "start_routine:ptr", "arg:ptr"});
        libcFuncs.put("pthread_join", new String[]{"thread:ptr", "retval:ptr"});
        libcFuncs.put("pthread_attr_init", new String[]{"attr:ptr"});
        libcFuncs.put("pthread_attr_destroy", new String[]{"attr:ptr"});
        libcFuncs.put("pthread_mutex_lock", new String[]{"mutex:ptr"});
        libcFuncs.put("pthread_mutex_unlock", new String[]{"mutex:ptr"});
        // Crypto / Random
        libcFuncs.put("rand", new String[]{});
        libcFuncs.put("srand", new String[]{"seed:int"});
        libcFuncs.put("arc4random", new String[]{});
        libcFuncs.put("arc4random_buf", new String[]{"buf:ptr", "nbytes:size"});
        libcFuncs.put("arc4random_uniform", new String[]{"upper_bound:int"});
        
        libcFuncs.put("time", new String[]{"tloc:ptr"});
        libcFuncs.put("gettimeofday", new String[]{"tv:ptr", "tz:ptr"});
        libcFuncs.put("clock_gettime", new String[]{"clk_id:int", "tp:ptr"});
        libcFuncs.put("srand48", new String[]{"seed:int"});
        libcFuncs.put("lrand48", new String[]{});
        libcFuncs.put("drand48", new String[]{});
    }

    @Override
    public boolean canHandle(String moduleName, String symbolName, boolean isJni) {
        if (isJni) return false;
        // Handle common architectures where standard libc functions can be routed
        if ("libc.so".equals(moduleName)) return true;
        // Even if moduleName is unknown due to thumb unresolved PLT, if the symbolName matches our list exactly
        if (symbolName != null && libcFuncs.containsKey(symbolName)) {
            return true;
        }
        return false;
    }

    @Override
    public String formatCall(AssemblyCodeTextDumper.PendingCall call, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        String funcName = call.funcName;
        String[] argsTypes = libcFuncs.get(funcName);
        
        if (argsTypes == null && !"libc.so".equals(call.moduleName)) {
            return null; // fallback to general parser since we aren't sure it's actually libc if module name is lost
        }
        
        StringBuilder sb = new StringBuilder(call.moduleName != null ? call.moduleName + " " : "").append(funcName).append("(");
        
        if (argsTypes != null) {
            String formatStr = null;
            for (int i = 0; i < argsTypes.length; i++) {
                if (i > 0) sb.append(", ");
                String[] parts = argsTypes[i].split(":");
                String name = parts[0];
                String type = parts[1];
                
                long arg = dumper.getArgRegValue(backend, i, is64Bit);
                sb.append(dumper.formatArgValue(type, arg, backend));
                
                if ("format".equals(name) && "str".equals(type)) {
                    formatStr = dumper.readStringSafe(backend, arg);
                }
            }
            
            // Auto vararg extraction for printf / scanf family
            if (formatStr != null && (funcName.contains("printf") || funcName.contains("scanf") || funcName.contains("syslog"))) {
                if (funcName.startsWith("v")) {
                    sb.append(", va_list");
                } else {
                    List<String> specifiers = dumper.extractFormatSpecifiers(formatStr);
                    int argIndex = argsTypes.length;
                    for (String spec : specifiers) {
                        sb.append(", ");
                        long arg = dumper.getArgRegValue(backend, argIndex++, is64Bit);
                        if (spec.endsWith("s")) {
                            sb.append(dumper.formatArgValue("str", arg, backend));
                        } else if (spec.endsWith("c")) {
                            sb.append(dumper.formatArgValue("char", arg, backend));
                        } else if (spec.endsWith("p")) {
                            sb.append(dumper.formatArgValue("ptr", arg, backend));
                        } else {
                            sb.append(arg).append(" (0x").append(Long.toHexString(arg)).append(")");
                        }
                    }
                }
            }
        } else {
            sb.append("X0=0x").append(Long.toHexString(dumper.getArgRegValue(backend, 0, is64Bit)))
              .append(", X1=0x").append(Long.toHexString(dumper.getArgRegValue(backend, 1, is64Bit)))
              .append(", X2=0x").append(Long.toHexString(dumper.getArgRegValue(backend, 2, is64Bit)));
        }
        sb.append(")");
        return sb.toString();
    }

    @Override
    public String formatReturnValue(AssemblyCodeTextDumper.PendingCall call, long retVal, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        String funcName = call.funcName;
        if ("strlen".equals(funcName)) {
            return String.valueOf(retVal);
        }
        if ("strcmp".equals(funcName) || "memcmp".equals(funcName) || "strncmp".equals(funcName)) {
            return String.valueOf((int)retVal) + (retVal == 0 ? " (equal)" : "");
        }
        if ("malloc".equals(funcName) || "calloc".equals(funcName) || "realloc".equals(funcName) || "mmap".equals(funcName)) {
            return "0x" + Long.toHexString(retVal);
        } else if ("toupper".equals(funcName) || "tolower".equals(funcName)) {
            long c = retVal & 0xFF;
            if (c >= 32 && c <= 126) return String.format("%d ('%c')", retVal, (char)c);
            else if (c == 0) return retVal + " ('\\0')";
            return String.valueOf(retVal);
        }
        return null;
    }

    @Override
    public void printPostReturnMemoryDump(PrintStream out, AssemblyCodeTextDumper.PendingCall call, long retVal, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        try {
            String f = call.funcName;
            
            // 1. String-based memory updates
            long destStr = 0;
            if (f.contains("printf") || f.contains("strcpy") || f.contains("strcat") || "memset".equals(f)) {
                destStr = call.args[0];
            } else if ("__system_property_get".equals(f)) {
                destStr = call.args[1];
            }
            
            if (destStr != 0) {
                String s = dumper.readStringSafe(backend, destStr);
                if (s != null) {
                    out.println("    mem_upd 0x" + Long.toHexString(destStr) + " -> \"" + s + "\"");
                }
            }
            
            // 2. Binary buffer memory updates (Hexdump)
            long destBuf = 0;
            long size = 0;
            if ("memcpy".equals(f) || "memmove".equals(f)) {
                destBuf = call.args[0]; size = call.args[2];
            } else if ("bzero".equals(f)) {
                destBuf = call.args[0]; size = call.args[1];
            } else if ("read".equals(f) || "pread".equals(f) || "recv".equals(f) || "recvfrom".equals(f)) {
                if (retVal > 0) { destBuf = call.args[1]; size = retVal; }
            } else if ("fread".equals(f)) {
                if (retVal > 0) { destBuf = call.args[0]; size = retVal * call.args[1]; }
            } else if ("arc4random_buf".equals(f)) {
                destBuf = call.args[0]; size = call.args[1];
            }
            
            if (destBuf != 0 && size > 0) {
                int readSize = size > 4096 ? 4096 : (int) size;
                byte[] data = backend.mem_read(destBuf, readSize);
                String label = (size > 4096 ? "[Truncated " + readSize + "/" + size + "] " : "") + "Hex Updated 0x" + Long.toHexString(destBuf);
                out.println(com.github.unidbg.utils.Inspector.inspectString(data, label));
            }
        } catch (Exception ignored) {}
    }
}
