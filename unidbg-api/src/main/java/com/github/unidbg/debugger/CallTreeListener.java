package com.github.unidbg.debugger;

import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.utils.SymbolResolver;

import java.io.PrintStream;

public class CallTreeListener extends FunctionCallListener {  // FunctionCallListener 是 abstract class
    private int depth = 0;
    private final PrintStream out;
    private final Module module;
    private final Emulator<?> emulator;

    public CallTreeListener(PrintStream out, Module module, Emulator<?> emulator) { this.out = out; this.module = module; this.emulator = emulator;}

    @Override
    public void onCall(Emulator<?> emulator, long caller, long target) {
        for (int i = 0; i < depth; i++) out.print("│ ");
        out.println("├─ " + resolveName(caller, target));
        depth++;
    }

    private String resolveName(long caller, long target) {
        SymbolResolver symbolResolver = new SymbolResolver(this.module, this.emulator);
        return symbolResolver.resolve(target, caller);
    }

    @Override
    public void postCall(Emulator<?> emulator, long caller, long target, Number[] args) {
        depth--;
    }
}
