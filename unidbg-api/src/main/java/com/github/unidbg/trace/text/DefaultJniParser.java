package com.github.unidbg.trace.text;

import com.github.unidbg.*;
import com.github.unidbg.arm.backend.Backend;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

public class DefaultJniParser implements TraceCallParser {

    private final Map<String, String[]> jniArgs = new HashMap<>();

    public static final String[] JNI_METHODS = {
        "reserved0", "reserved1", "reserved2", "reserved3", "GetVersion", "DefineClass", "FindClass",
        "FromReflectedMethod", "FromReflectedField", "ToReflectedMethod", "GetSuperclass", "IsAssignableFrom",
        "ToReflectedField", "Throw", "ThrowNew", "ExceptionOccurred", "ExceptionDescribe", "ExceptionClear",
        "FatalError", "PushLocalFrame", "PopLocalFrame", "NewGlobalRef", "DeleteGlobalRef", "DeleteLocalRef",
        "IsSameObject", "NewLocalRef", "EnsureLocalCapacity", "AllocObject", "NewObject", "NewObjectV",
        "NewObjectA", "GetObjectClass", "IsInstanceOf", "GetMethodID", "CallObjectMethod", "CallObjectMethodV",
        "CallObjectMethodA", "CallBooleanMethod", "CallBooleanMethodV", "CallBooleanMethodA", "CallByteMethod",
        "CallByteMethodV", "CallByteMethodA", "CallCharMethod", "CallCharMethodV", "CallCharMethodA",
        "CallShortMethod", "CallShortMethodV", "CallShortMethodA", "CallIntMethod", "CallIntMethodV",
        "CallIntMethodA", "CallLongMethod", "CallLongMethodV", "CallLongMethodA", "CallFloatMethod",
        "CallFloatMethodV", "CallFloatMethodA", "CallDoubleMethod", "CallDoubleMethodV", "CallDoubleMethodA",
        "CallVoidMethod", "CallVoidMethodV", "CallVoidMethodA", "GetNonvirtualObjectMethod",
        "GetNonvirtualObjectMethodV", "GetNonvirtualObjectMethodA", "GetNonvirtualBooleanMethod",
        "GetNonvirtualBooleanMethodV", "GetNonvirtualBooleanMethodA", "GetNonvirtualByteMethod",
        "GetNonvirtualByteMethodV", "GetNonvirtualByteMethodA", "GetNonvirtualCharMethod",
        "GetNonvirtualCharMethodV", "GetNonvirtualCharMethodA", "GetNonvirtualShortMethod",
        "GetNonvirtualShortMethodV", "GetNonvirtualShortMethodA", "GetNonvirtualIntMethod",
        "GetNonvirtualIntMethodV", "GetNonvirtualIntMethodA", "GetNonvirtualLongMethod",
        "GetNonvirtualLongMethodV", "GetNonvirtualLongMethodA", "GetNonvirtualFloatMethod",
        "GetNonvirtualFloatMethodV", "GetNonvirtualFloatMethodA", "GetNonvirtualDoubleMethod",
        "GetNonvirtualDoubleMethodV", "GetNonvirtualDoubleMethodA", "GetNonvirtualVoidMethod",
        "GetNonvirtualVoidMethodV", "GetNonvirtualVoidMethodA", "GetFieldID", "GetObjectField",
        "GetBooleanField", "GetByteField", "GetCharField", "GetShortField", "GetIntField", "GetLongField",
        "GetFloatField", "GetDoubleField", "SetObjectField", "SetBooleanField", "SetByteField", "SetCharField",
        "SetShortField", "SetIntField", "SetLongField", "SetFloatField", "SetDoubleField", "GetStaticMethodID",
        "CallStaticObjectMethod", "CallStaticObjectMethodV", "CallStaticObjectMethodA", "CallStaticBooleanMethod",
        "CallStaticBooleanMethodV", "CallStaticBooleanMethodA", "CallStaticByteMethod", "CallStaticByteMethodV",
        "CallStaticByteMethodA", "CallStaticCharMethod", "CallStaticCharMethodV", "CallStaticCharMethodA",
        "CallStaticShortMethod", "CallStaticShortMethodV", "CallStaticShortMethodA", "CallStaticIntMethod",
        "CallStaticIntMethodV", "CallStaticIntMethodA", "CallStaticLongMethod", "CallStaticLongMethodV",
        "CallStaticLongMethodA", "CallStaticFloatMethod", "CallStaticFloatMethodV", "CallStaticFloatMethodA",
        "CallStaticDoubleMethod", "CallStaticDoubleMethodV", "CallStaticDoubleMethodA", "CallStaticVoidMethod",
        "CallStaticVoidMethodV", "CallStaticVoidMethodA", "GetStaticFieldID", "GetStaticObjectField",
        "GetStaticBooleanField", "GetStaticByteField", "GetStaticCharField", "GetStaticShortField",
        "GetStaticIntField", "GetStaticLongField", "GetStaticFloatField", "GetStaticDoubleField",
        "SetStaticObjectField", "SetStaticBooleanField", "SetStaticByteField", "SetStaticCharField",
        "SetStaticShortField", "SetStaticIntField", "SetStaticLongField", "SetStaticFloatField",
        "SetStaticDoubleField", "NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars",
        "NewStringUTF", "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength",
        "NewObjectArray", "GetObjectArrayElement", "SetObjectArrayElement", "NewBooleanArray", "NewByteArray",
        "NewCharArray", "NewShortArray", "NewIntArray", "NewLongArray", "NewFloatArray", "NewDoubleArray",
        "GetBooleanArrayElements", "GetByteArrayElements", "GetCharArrayElements", "GetShortArrayElements",
        "GetIntArrayElements", "GetLongArrayElements", "GetFloatArrayElements", "GetDoubleArrayElements",
        "ReleaseBooleanArrayElements", "ReleaseByteArrayElements", "ReleaseCharArrayElements",
        "ReleaseShortArrayElements", "ReleaseIntArrayElements", "ReleaseLongArrayElements",
        "ReleaseFloatArrayElements", "ReleaseDoubleArrayElements", "GetBooleanArrayRegion",
        "GetByteArrayRegion", "GetCharArrayRegion", "GetShortArrayRegion", "GetIntArrayRegion",
        "GetLongArrayRegion", "GetFloatArrayRegion", "GetDoubleArrayRegion", "SetBooleanArrayRegion",
        "SetByteArrayRegion", "SetCharArrayRegion", "SetShortArrayRegion", "SetIntArrayRegion",
        "SetLongArrayRegion", "SetFloatArrayRegion", "SetDoubleArrayRegion", "RegisterNatives",
        "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion",
        "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical",
        "GetStringCritical", "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef",
        "ExceptionCheck", "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity",
        "GetObjectRefType"
    };

    public DefaultJniParser() {
        jniArgs.put("GetVersion", new String[]{});
        jniArgs.put("DefineClass", new String[]{"name:str", "loader:jobject", "buf:buf", "bufLen:size"});
        jniArgs.put("FindClass", new String[]{"name:str"});
        jniArgs.put("FromReflectedMethod", new String[]{"method:jobject"});
        jniArgs.put("FromReflectedField", new String[]{"field:jobject"});
        jniArgs.put("ToReflectedMethod", new String[]{"cls:jclass", "methodID:jmethodID", "isStatic:int"});
        jniArgs.put("GetSuperclass", new String[]{"clazz:jclass"});
        jniArgs.put("IsAssignableFrom", new String[]{"clazz1:jclass", "clazz2:jclass"});
        jniArgs.put("ToReflectedField", new String[]{"cls:jclass", "fieldID:jfieldID", "isStatic:int"});
        jniArgs.put("Throw", new String[]{"obj:jobject"});
        jniArgs.put("ThrowNew", new String[]{"clazz:jclass", "message:str"});
        jniArgs.put("ExceptionOccurred", new String[]{});
        jniArgs.put("ExceptionDescribe", new String[]{});
        jniArgs.put("ExceptionClear", new String[]{});
        jniArgs.put("FatalError", new String[]{"msg:str"});
        jniArgs.put("PushLocalFrame", new String[]{"capacity:int"});
        jniArgs.put("PopLocalFrame", new String[]{"result:jobject"});
        jniArgs.put("NewGlobalRef", new String[]{"obj:jobject"});
        jniArgs.put("DeleteGlobalRef", new String[]{"globalRef:jobject"});
        jniArgs.put("DeleteLocalRef", new String[]{"localRef:jobject"});
        jniArgs.put("IsSameObject", new String[]{"ref1:jobject", "ref2:jobject"});
        jniArgs.put("NewLocalRef", new String[]{"ref:jobject"});
        jniArgs.put("EnsureLocalCapacity", new String[]{"capacity:int"});
        jniArgs.put("AllocObject", new String[]{"clazz:jclass"});
        jniArgs.put("NewObject", new String[]{"clazz:jclass", "methodID:jmethodID"});
        jniArgs.put("NewObjectV", new String[]{"clazz:jclass", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("NewObjectA", new String[]{"clazz:jclass", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("GetObjectClass", new String[]{"obj:jobject"});
        jniArgs.put("IsInstanceOf", new String[]{"obj:jobject", "clazz:jclass"});
        jniArgs.put("GetMethodID", new String[]{"clazz:jclass", "name:str", "sig:str"});
        jniArgs.put("CallObjectMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallObjectMethodV", new String[]{"obj:jobject", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("CallObjectMethodA", new String[]{"obj:jobject", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("CallBooleanMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallByteMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallCharMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallShortMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallIntMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallLongMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallFloatMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallDoubleMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallVoidMethod", new String[]{"obj:jobject", "methodID:jmethodID"});
        jniArgs.put("CallVoidMethodV", new String[]{"obj:jobject", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("CallVoidMethodA", new String[]{"obj:jobject", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("GetFieldID", new String[]{"clazz:jclass", "name:str", "sig:str"});
        jniArgs.put("GetObjectField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetBooleanField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetByteField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetCharField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetShortField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetIntField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetLongField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetFloatField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("GetDoubleField", new String[]{"obj:jobject", "fieldID:jfieldID"});
        jniArgs.put("SetObjectField", new String[]{"obj:jobject", "fieldID:jfieldID", "val:jobject"});
        jniArgs.put("SetBooleanField", new String[]{"obj:jobject", "fieldID:jfieldID", "val:int"});
        jniArgs.put("SetByteField", new String[]{"obj:jobject", "fieldID:jfieldID", "val:int"});
        jniArgs.put("SetCharField", new String[]{"obj:jobject", "fieldID:jfieldID", "val:char"});
        jniArgs.put("SetShortField", new String[]{"obj:jobject", "fieldID:jfieldID", "val:int"});
        jniArgs.put("SetIntField", new String[]{"obj:jobject", "fieldID:jfieldID", "val:int"});
        jniArgs.put("SetLongField", new String[]{"obj:jobject", "fieldID:jfieldID", "val:int"});
        jniArgs.put("GetStaticMethodID", new String[]{"clazz:jclass", "name:str", "sig:str"});
        jniArgs.put("CallStaticObjectMethod", new String[]{"clazz:jclass", "methodID:jmethodID"});
        jniArgs.put("CallStaticObjectMethodV", new String[]{"clazz:jclass", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("CallStaticObjectMethodA", new String[]{"clazz:jclass", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("CallStaticBooleanMethod", new String[]{"clazz:jclass", "methodID:jmethodID"});
        jniArgs.put("CallStaticIntMethod", new String[]{"clazz:jclass", "methodID:jmethodID"});
        jniArgs.put("CallStaticLongMethod", new String[]{"clazz:jclass", "methodID:jmethodID"});
        jniArgs.put("CallStaticVoidMethod", new String[]{"clazz:jclass", "methodID:jmethodID"});
        jniArgs.put("CallStaticVoidMethodV", new String[]{"clazz:jclass", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("CallStaticVoidMethodA", new String[]{"clazz:jclass", "methodID:jmethodID", "args:ptr"});
        jniArgs.put("GetStaticFieldID", new String[]{"clazz:jclass", "name:str", "sig:str"});
        jniArgs.put("GetStaticObjectField", new String[]{"clazz:jclass", "fieldID:jfieldID"});
        jniArgs.put("GetStaticIntField", new String[]{"clazz:jclass", "fieldID:jfieldID"});
        jniArgs.put("SetStaticObjectField", new String[]{"clazz:jclass", "fieldID:jfieldID", "val:jobject"});
        jniArgs.put("SetStaticIntField", new String[]{"clazz:jclass", "fieldID:jfieldID", "val:int"});
        jniArgs.put("NewString", new String[]{"unicodeChars:str", "len:size"});
        jniArgs.put("GetStringLength", new String[]{"string:jobject"});
        jniArgs.put("GetStringChars", new String[]{"string:jobject", "isCopy:ptr"});
        jniArgs.put("ReleaseStringChars", new String[]{"string:jobject", "chars:str"});
        jniArgs.put("NewStringUTF", new String[]{"bytes:str"});
        jniArgs.put("GetStringUTFLength", new String[]{"string:jobject"});
        jniArgs.put("GetStringUTFChars", new String[]{"string:jobject", "isCopy:ptr"});
        jniArgs.put("ReleaseStringUTFChars", new String[]{"string:jobject", "utf:str"});
        jniArgs.put("GetArrayLength", new String[]{"array:jobject"});
        jniArgs.put("NewObjectArray", new String[]{"length:size", "elementClass:jclass", "initialElement:jobject"});
        jniArgs.put("GetObjectArrayElement", new String[]{"array:jobject", "index:size"});
        jniArgs.put("SetObjectArrayElement", new String[]{"array:jobject", "index:size", "val:jobject"});
        jniArgs.put("NewByteArray", new String[]{"length:size"});
        jniArgs.put("NewIntArray", new String[]{"length:size"});
        jniArgs.put("GetByteArrayElements", new String[]{"array:jobject", "isCopy:ptr"});
        jniArgs.put("ReleaseByteArrayElements", new String[]{"array:jobject", "elems:buf", "mode:int"});
        jniArgs.put("GetIntArrayElements", new String[]{"array:jobject", "isCopy:ptr"});
        jniArgs.put("ReleaseIntArrayElements", new String[]{"array:jobject", "elems:buf", "mode:int"});
        jniArgs.put("GetByteArrayRegion", new String[]{"array:jobject", "start:size", "len:size", "buf:buf"});
        jniArgs.put("SetByteArrayRegion", new String[]{"array:jobject", "start:size", "len:size", "buf:buf"});
        jniArgs.put("RegisterNatives", new String[]{"clazz:jclass", "methods:ptr", "nMethods:int"});
        jniArgs.put("UnregisterNatives", new String[]{"clazz:jclass"});
        jniArgs.put("GetJavaVM", new String[]{"vm:ptr"});
        jniArgs.put("GetPrimitiveArrayCritical", new String[]{"array:jobject", "isCopy:ptr"});
        jniArgs.put("ReleasePrimitiveArrayCritical", new String[]{"array:jobject", "carray:buf", "mode:int"});
    }

    @Override
    public boolean canHandle(String moduleName, String symbolName, boolean isJni) {
        return isJni;
    }

    @Override
    public String formatCall(AssemblyCodeTextDumper.PendingCall call, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        String[] args = jniArgs.get(call.funcName);
        StringBuilder sb = new StringBuilder("JNIEnv ").append(call.funcName).append("(");
        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                if (i > 0) sb.append(", ");
                String type = args[i].split(":")[1];
                // JNI args start at arg1 because arg0 is JNIEnv*
                long arg = dumper.getArgRegValue(backend, i + 1, is64Bit);
                sb.append(dumper.formatArgValue(type, arg, backend));
            }
        } else {
            // Unmapped JNI methods, just print general params
            for (int i = 1; i <= 3; i++) {
                if (i > 1) sb.append(", ");
                long arg = dumper.getArgRegValue(backend, i, is64Bit);
                sb.append("0x").append(Long.toHexString(arg));
            }
        }
        sb.append(")");
        return sb.toString();
    }

    @Override
    public String formatReturnValue(AssemblyCodeTextDumper.PendingCall call, long retVal, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        String funcName = call.funcName == null ? "" : call.funcName;
        Map<Long, String> jniIdMap = dumper.getJniIdMap();

        if ("FindClass".equals(funcName) || "GetObjectClass".equals(funcName) || "GetSuperclass".equals(funcName)) {
            if (retVal != 0 && "FindClass".equals(funcName)) {
                String className = dumper.readStringSafe(backend, call.args[1]);
                if (className != null) {
                    jniIdMap.put(retVal, className);
                    return "0x" + Long.toHexString(retVal) + " class " + className;
                }
            }
        } else if (funcName.endsWith("MethodID")) {
            if (retVal != 0) {
                String methodName = dumper.readStringSafe(backend, call.args[2]);
                String methodSig = dumper.readStringSafe(backend, call.args[3]);
                if (methodName != null && methodSig != null) {
                    jniIdMap.put(retVal, methodName + methodSig);
                    return "0x" + Long.toHexString(retVal) + "  " + methodName + methodSig;
                }
            }
        } else if (funcName.endsWith("FieldID")) {
            if (retVal != 0) {
                String fieldName = dumper.readStringSafe(backend, call.args[2]);
                String fieldSig = dumper.readStringSafe(backend, call.args[3]);
                if (fieldName != null && fieldSig != null) {
                    jniIdMap.put(retVal, fieldName + " " + fieldSig);
                    return "0x" + Long.toHexString(retVal) + "  " + fieldName + " " + fieldSig;
                }
            }
        } else if (funcName.startsWith("GetString") && funcName.contains("Chars")) {
            if (retVal != 0) {
                String s = dumper.readStringSafe(backend, retVal);
                return "0x" + Long.toHexString(retVal) + " -> \"" + dumper.escapeString(s) + "\"";
            }
        }
        
        if ("GetArrayLength".equals(funcName)) {
            return String.valueOf(retVal);
        }
        if ("ExceptionCheck".equals(funcName) || "IsSameObject".equals(funcName)) {
            return (retVal != 0) ? "true" : "false";
        }
        
        return null;
    }

    @Override
    public void printPostReturnMemoryDump(PrintStream out, AssemblyCodeTextDumper.PendingCall call, long retVal, Backend backend, boolean is64Bit, Emulator<?> emulator, AssemblyCodeTextDumper dumper) {
        String funcName = call.funcName;
        if (funcName == null) return;
        long srcAddr = 0;
        long length = 0;
        if (funcName.equals("SetByteArrayRegion") || funcName.equals("SetShortArrayRegion") || funcName.equals("SetIntArrayRegion") || funcName.equals("SetLongArrayRegion") || funcName.equals("SetFloatArrayRegion") || funcName.equals("SetDoubleArrayRegion") || funcName.equals("SetBooleanArrayRegion") || funcName.equals("SetCharArrayRegion")) {
            srcAddr = call.args[4];
            length = call.args[3];
        } else if (funcName.equals("GetByteArrayRegion") || funcName.equals("GetIntArrayRegion") || funcName.equals("GetShortArrayRegion") || funcName.equals("GetLongArrayRegion")) {
            srcAddr = call.args[4];
            length = call.args[3];
        } else if (funcName.equals("GetByteArrayElements") || funcName.equals("GetIntArrayElements") || funcName.equals("GetShortArrayElements") || funcName.equals("GetLongArrayElements")) {
            if (retVal != 0) {
                srcAddr = retVal;
                long arrLen = call.args[1];
                if (arrLen != 0) length = arrLen;
            }
        } else if (funcName.equals("NewStringUTF")) {
            if (retVal != 0) {
                String s = dumper.readStringSafe(backend, retVal);
                if (s != null) {
                    out.println("  -> \"" + dumper.escapeString(s) + "\"");
                }
            }
            return;
        }
        if (srcAddr != 0 && length > 0 && length <= 4096) {
            int readLen = (int) length;
            byte[] data = backend.mem_read(srcAddr, readLen);
            out.println("hexdump at address 0x" + Long.toHexString(srcAddr) + " with length 0x" + Long.toHexString(length) + ":");
            StringBuilder hex = new StringBuilder();
            StringBuilder ascii = new StringBuilder();
            for (int offset = 0; offset < data.length; offset++) {
                if (offset % 16 == 0) {
                    if (offset > 0) {
                        out.println(hex.toString() + " |" + ascii.toString() + "|");
                    }
                    hex.setLength(0);
                    ascii.setLength(0);
                    hex.append(String.format("%016x:", srcAddr + offset));
                }
                if (hex.length() > 0 && offset % 2 == 0 && offset % 16 != 0) hex.append(' ');
                hex.append(String.format("%02x", data[offset] & 0xFF));
                ascii.append((data[offset] >= 32 && data[offset] <= 126) ? (char) data[offset] : '.');
            }
            if (hex.length() > 0) {
                int padding = 50 - hex.length();
                for (int i = 0; i < padding; i++) hex.append(' ');
                out.println(hex.toString() + " |" + ascii.toString() + "|");
            }
        }
    }
}
