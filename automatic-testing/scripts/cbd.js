
var target_module_names = ["libc.so", "liblog.so"];
var count = 1;

var hookFunctions = [
    {
        moduleName: "libc.so",
        funcName: "ioctl", // Function name goes here
        onEnter: function(arg){
            var name = "ioctl";
            this.num = arg[1]; // store ioctl number
            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2]);
            if (arg[1] == "0x401c6f40") {
                // firmware upload
//                var buffer = arg[2].readByteArray(800);
//                printLog(buffer);
            }
            else if (arg[1] == "0x40106f53") {
                // security request
                if (count % 3 == 0) {
                    // return 0 to bypass
                }

                printLog(count);
                ++count;
            }
        },
        onLeave: function(ret){
            if (this.num == "0x40106f53") {
                printLog("[OnLeave] " + ret);
            }
            else if (this.num == "0x40046f22") {
                printLog("[OnLeave] " + ret);
            }
        }
    },

//    {
//        moduleName: "libc.so",
//        funcName: "read", // Function name goes here
//        onEnter: function(arg){
//            var name = "read";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2]);
////            var buffer = arg[1].readByteArray(500);
////            printLog(buffer);
//        },
//        onLeave: function(ret){
//        }
//    },

    {
        moduleName: "libc.so",
        funcName: "__open_2", // Function name goes here
        onEnter: function(arg){
            var name = "__open_2";
            printLog("[OnEnter] " + name + " " + Memory.readCString(arg[0]));
        },
        onLeave: function(ret){
        }
    },

    {
        moduleName: "libc.so",
        funcName: "strerror", // Function name goes here
        onEnter: function(arg){
            var name = "strerror";
            printLog("[OnEnter] " + name + " " + arg[0]);
        },
        onLeave: function(ret){
            var name = "strerror";
            printLog("[OnLeave] " + name + " " + Memory.readCString(ret));
        }
    },

    {
        moduleName: "liblog.so",
        funcName: "__android_log_buf_print", // Function name goes here
        onEnter: function(arg){
            var name = "__android_log_buf_print";
            printLog("[OnEnter] " + name + " " + Memory.readCString(arg[3]) + Memory.readCString(arg[4]));
        },
        onLeave: function(ret){
        }
    },

    {
        moduleName: "cbd",
        funcName: "std_security_request",
        offset: 0x186d4,
        onEnter: function(arg){
            var name = "std_security_request";
            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1] + " " + arg[2] + " " + arg[3]);
        },
        onLeave: function(ret){
        }
    },

//    {
//        moduleName: "liblog.so",
//        funcName: "dprintf", // Function name goes here
//        onEnter: function(arg){
//            var name = "dprintf";
//            printLog("[OnEnter] " + name + " " + Memory.readCString(arg[1]) + Memory.readCString(arg[4]));
//        },
//        onLeave: function(ret){
//        }
//    },

//    {
//        moduleName: "libc.so",
//        funcName: "printf", // Function name goes here
//        onEnter: function(arg){
//            var name = "printf";
//            printLog("[OnEnter] " + name + " " + Memory.readCString(arg[0] + Memory.readCString(arg[4])));
//        },
//        onLeave: function(ret){
//        }
//    },
//
//    {
//        moduleName: "libc.so",
//        funcName: "dlopen", // Function name goes here
//        onEnter: function(arg){
//            var name = "dlopen";
//            printLog("[OnEnter] " + name + " " + Memory.readCString(arg[0] + Memory.readCString(arg[4])));
//        },
//        onLeave: function(ret){
//        }
//    },

//    {
//        moduleName: "libc.so",
//        funcName: "__poll_chk", // Function name goes here
//        onEnter: function(arg){
//            var name = "__poll_chk";
//            printLog("[OnEnter] " + name + " " + Memory.readCString(arg[0]));
//        },
//        onLeave: function(ret){
//        }
//    },

//    {
//        moduleName: "cbd",
//        funcName: "upload_image",
//        offset: 0x1d564,
//        onEnter: function(arg){
//            var name = "upload_image";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1]);
//        },
//        onLeave: function(ret){
//        }
//    },
//
//    {
//        moduleName: "cbd",
//        funcName: "upload_image2",
//        offset: 0x14938,
//        onEnter: function(arg){
//            var name = "upload_image2";
//            printLog("[OnEnter] " + name + " " + arg[0] + " " + arg[1]);
//        },
//        onLeave: function(ret){
//        }
//    },


];


printLog("Start hooking module cbd");

hookFunctionList();


function hookFunction(hookFunc) {

    if (hookFunc.offset) {
        hookFunctionWithOffset(hookFunc);
        return;
    }

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

//    if (hookFunc.funcName == "ioctl")
//        replaceFunction(hookFunc);

    Interceptor.attach(exp, {
        onEnter: hookFunc.onEnter,
        onLeave: hookFunc.onLeave
    });
}


function hookFunctionWithOffset(hookFunc) {
    var base = Module.findBaseAddress(hookFunc.moduleName);

    // intercepting function
    printLog("Placing function hook on: " + hookFunc.funcName + " at " + base.add(hookFunc.offset));

    Interceptor.attach(base.add(hookFunc.offset), {
        onEnter: hookFunc.onEnter,
        onLeave: hookFunc.onLeave
    });
}


function replaceFunction(hookFunc) {

    var oldFunc = null;
    if (hookFunc.offset)
        oldFunc = base.add(hookFunc.offset);
    else
        oldFunc = Module.findExportByName(hookFunc.moduleName, hookFunc.funcName);

    // replace native function implementation
    printLog("Replacing function of " + hookFunc.funcName + " at " + oldFunc);
    const newFunc = new NativeFunction(oldFunc, 'int', ['int', 'int', 'pointer']); // original function impl
    Interceptor.replace(oldFunc, new NativeCallback((arg0, arg1, arg2) => {
        if (arg1 == 0x40106f53) {
            printLog("Invoking replaced function ");
            return 0x0;
        }
        else {
            var res = newFunc(arg0, arg1, arg2);
            return res;
        }
    }, 'int', ['int', 'int', 'pointer']));
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
}


function bytesToHex(byteArray) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}