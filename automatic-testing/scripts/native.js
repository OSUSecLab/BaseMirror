// Android native hooks By @709924470
// CC-BY-NC 4.0
var moduleName = "rild"; // Module name goes here

//var target_module_names = ["libril.so", "librilutils.so", "libsec-ril.so", "libsec-ril-dsds.so", "rild"];
//var target_module_names = ["libsec-ril-dsds.so", "libsec-ril.so"];
var target_module_names = ["liblog.so"];


var hookFunctions = [
//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN11MiscManager11HandleEventER7Message",
//        onEnter: function(arg){
//            var name = "_ZN11MiscManager11HandleEventER7Message";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2] + " " + arg[3]);
//
//            var eventPtr = arg[1].add(36);
//            var event = Memory.readInt(eventPtr);
//
//            // overwrite event
////            var newEvent = 116 // 0x74, onModemStateChanged
////            eventPtr.writeInt(newEvent);
////            send("Overwrite event " + eventPtr + " from " + event + " to " + newEvent);
////
////            // overwrite modem state
////            var statePtr = arg[1].add(48);
////            var state = Memory.readInt(statePtr);
////            var newState = 2;
////            statePtr.writeInt(newState);
////            send("Overwrite modem state " + statePtr + " from " + state + " to " + newState);
//
//        },
//        onLeave: function(ret){
////            send("Return " + ret);
//        }
//    },
//
//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN11MiscManager19OnModemStateChangedE10ModemState", // Function name goes here
//        onEnter: function(arg){
//            var name = "_ZN11MiscManager19OnModemStateChangedE10ModemState";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2] + " " + arg[3]);
//        },
//        onLeave: function(ret){
//        }
//    },
//
//
//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN12ModemFactory20EnterModemUploadModeEv", // Function name goes here
//        onEnter: function(arg){
//            var name = "_ZN12ModemFactory20EnterModemUploadModeEv";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2] + " " + arg[3]);
//        },
//        onLeave: function(ret){
//        }
//    },
//
//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN6SecRil20EnterModemUploadModeEv", // Function name goes here
//        onEnter: function(arg){
//            var name = "_ZN6SecRil20EnterModemUploadModeEv";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2] + " " + arg[3]);
//        },
//        onLeave: function(ret){
//        }
//    },
//
//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN11MiscManager14OnAtCmdForwardEP16FactoryCmdLength", // Function name goes here
//        onEnter: function(arg){
//            var name = "_ZN11MiscManager14OnAtCmdForwardEP16FactoryCmdLength";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2] + " " + arg[3]);
//        },
//        onLeave: function(ret){
//        }
//    },

    {
        moduleName: "liblog.so",
        funcName: "__android_log_buf_print", // Function name goes here
        onEnter: function(arg){
            var name = "__android_log_buf_print";
            printLog("[OnEnter] " + name + " " + Memory.readCString(arg[3]));
        },
        onLeave: function(ret){
        }
    },
];


printLog("Start hooking module " + moduleName);

hookFunctionList();

//Process.enumerateModules({
//    onMatch: function(module) {
////        send(module.name);
//        if (target_module_names.includes(module.name)) {
//            // module find
//            printLog("[ModuleOnMatch] find " + module.name + " " + module.base + " " + module.size + " " + module.path);
//
//            var exports = module.enumerateExports();
//            for (var i=0; i<exports.length; ++i) {
//                send(exports[i].name);
//                var exp = Module.findExportByName(module.name, exports[i].name);
//                try {
//                    Interceptor.attach(exp, {
//                        onEnter: function(arg) {
//                            printLog("[OnEnter] " + exports[i].name + " " + arg[0] + " " + arg[1] + " " + arg[2]);
//                        },
//                        onLeave: function(ret) {
//                        }
//                    });
//                } catch (error) {
//                    continue;
//                }
//            }
//
////            for (var i=0; i<exports.length; ++i) {
//////                send(exports[i].name);
////                //if (exports[i].name.includes("MiscManager") && exports[i].name.includes("HandleEvent")) {
////                if (exports[i].name.includes("Upload")) {
////                    //send(exports[i].name);
////                    hookFunction(module.name, exports[i].name);
////                }
////            }
//        }
//    },
//
//    onComplete: function() {
//        send("[ModuleOnComplete]");
//    }
//});



function hookFunction(hookFunc) {

    var moduleName = hookFunc.moduleName;
    var fName = hookFunc.funcName;

    if (moduleName) {
        var exp = Module.findExportByName(moduleName, fName);
    }
    else {
        var exp = Module.findExportByName(null, fName);
    }

    if (exp != undefined) {
        printLog("Placing function hook on: " + fName + " at " + exp);
    }
    else {
        printLog("Unable to locate function " + fName + " from module " + moduleName);
        return;
    }

    Interceptor.attach(exp, {
        onEnter: hookFunc.onEnter,
        onLeave: hookFunc.onLeave
    });
}


function hookFunctionList() {
    for(var i = 0; i < hookFunctions.length; i++){
        hookFunction(hookFunctions[i]);
    }
}


function printLog(content) {
//    send(content); //print log
    writeFile(content); // log to file
}

function writeFile(content) {
    console.log(content);
//    var file = new File("/data/local/tmp/output.txt","a+");
//    file.write(content+"\n");
//    file.flush();
//    file.close();
}

