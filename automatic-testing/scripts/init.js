
var target_module_name = ["libsec-ril.so", "libsec-ril-dsds.so"];

var wait_id = 0xffff;
// var hooked = false;

var hookFunctions = [
    {
        moduleName: "libsec-ril.so",
        funcName: "_ZN11SecRilProxy21OnUnsolicitedResponseEiP7RilData", // Function name goes here
        onEnter: function(arg){
            var name = "SecRilProxy::OnUnsolicitedResponse";
            var id = arg[1].toInt32();
            var rawBuffer = arg[2].readByteArray(50)
            var buffer = buf2hex(rawBuffer);
            send("[OnEnter] id:" + id + " buf: " + buffer);

            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
        },
        onLeave: function(ret){
        }
    },
    {
        moduleName: "libsec-ril.so",
        funcName: "_ZN8IpcModem11SendMessageEPci", // Function name goes here
        onEnter: function(arg){
            var name = "IpcModem::SendMessage";
            var size = arg[2].toInt32();
            if(size > 100)
                size = 100
            var rawBuffer = arg[1].readByteArray(size)
            var buffer = buf2hex(rawBuffer);
            send("[OnEnter] " + name + " buf: " + buffer);

            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
        },
        onLeave: function(ret){
        }
    },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN11SecRilProxy17OnRequestCompleteEP7RequestiP7RilData",
    //     onEnter: function(arg){
    //         var name = "SecRilProxy::OnRequestComplete";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0] + " [1]:" + arg[1] + " [2]:" + arg[2]);
    //     },
    //     onLeave: function(ret){

    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "RIL_Init",
    //     onEnter: function(arg){
    //         var name = "RIL_Init";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0] + " [1]:" + arg[1] + " [2]:" + arg[2]);
    //     },
    //     onLeave: function(ret){

    //     }
    // },
    /***********DevIoctlIoChannel Related **************/
    
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN17DevIoctlIoChannel4ReadEPci",
    //     onEnter: function(arg){
    //         var name = "DevIoctlIoChannel::Read";
    //         send("[OnEnter] " + name + " " + "[0]: " + arg[0] + " [1]:" + arg[1] + " [2]:" + arg[2]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    /***********DevIoctlIoChannel Related **************/
    
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN9IoChannel4ReadEPci",
    //     onEnter: function(arg){
    //         var name = "IoChannel::Read";
    //         send("[OnEnter] " + name + " " + "[0]: " + arg[0] + " [1]:" + arg[1] + " [2]:" + arg[2]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    
    /***********IoChannelReader Related **************/
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN15IoChannelReader15OpenCommandPipeEv",
    //     onEnter: function(arg){
    //         var name = "IoChannelReader::AddIoChannel";
    //         send("[OnEnter] " + name + " " + "[0]: " + arg[0] + " [1]:" + arg[1]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN15IoChannelReaderC2EP5Modem",
    //     onEnter: function(arg){
    //         var name = "IoChannelReader::IoChannelReader";
    //         send("[OnEnter] " + name + " " + "[0]: " + arg[0] + " [1]:" + arg[1]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },

    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN15IoChannelReaderC1EP5Modem",
    //     onEnter: function(arg){
    //         var name = "IoChannelReader::IoChannelReader";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0] + " [1]:" + arg[1]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    
    /***********Branches of Nv::ProcessRfsMessage*********** */
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv20MakeRfsDirectoryNameEPc",
    //     onEnter: function(arg){
    //         var name = "Nv::MakeRfsDirectoryName";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0] + "[1]:" + arg[1] + "(" + Memory.readCString(arg[1]) + ")");
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv13ProcessNVReadEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessNVRead";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv18ProcessNvBufferingEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessNvBuffering";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },  
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv14ProcessNvWriteEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessNvWrite";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv15ProcessReadFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessReadFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv16ProcessWriteFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessWriteFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv16ProcessLseekFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessLseekFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv16ProcessCloseFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessCloseFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv14ProcessPutFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessPutFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv14ProcessGetFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessGetFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv17ProcessRenameFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessRenameFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv18ProcessGetFileInfoEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessGetFileInfo";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv17ProcessDeleteFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessDeleteFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv20ProcessMakeDirectoryEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessMakeDirectory";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv15ProcessOpenFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessOpenFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var lVar16 = Memory.readPointer(arg[0].add(0x380));
    //         var newVar = Memory.readUtf8String(lVar16.add(0xe));
    //         var newLen = Memory.readInt(lVar16.add(10));
    //         send("[OnEnter] "  + name + " "+ "path_string: " + newVar + " len: " + newLen);
    //         var newPath = "../../local/tmp/" + newVar;
    //         Memory.writeUtf8String(lVar16.add(0xe), newPath);
    //         var newPathLen = newPath.length;
    //         Memory.writeInt(lVar16.add(10), newPathLen);
    //         var newVar = Memory.readUtf8String(lVar16.add(0xe));
    //         var newLen = Memory.readInt(lVar16.add(10));
    //         send("[OnEnter] "  + name + " "+ "path_string: " + newVar + " len: " + newLen);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv26ProcessGetFileInfoByHandleEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessGetFileInfoByHandle";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv17ProcessCreateFileEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessCreateFile";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv17ProcessNVWriteAllEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessNVWriteAll";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv23ProcessNVBufferStartEndEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessNVBufferStartEnd";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv16ProcessNVRestoreEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessNVRestore";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },

    
    
    
    
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv4InitEP8NvConfig",
    //     onEnter: function(arg){
    //         var name = "Nv::Init";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0] + " [1]:" + arg[1]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },

    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN8IpcModem25ProcessRfsMessageReceivedEPci",
    //     onEnter: function(arg){
    //         var name = "IpcModem::ProcessRfsMessageReceived";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0] + " [1]:" + arg[1] + " [2]:" + arg[2]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv16ProcessRfsPacketEPci",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessRfsPacket";
    //         send("[OnEnter] "  + name + " "+"[0]: " + arg[0] + " [1]:" + arg[1] + " [2] " + arg[2]);
    //         const bufAddress = arg[1];
    //         const length = arg[2].toInt32();
    //         const byteArray = bufAddress.readByteArray(length);
    //         send(name + " buffer: " + buf2hex(byteArray));
    //         var baseAddress = Module.findBaseAddress("libsec-ril.so");
    //         send(name + " baseAddress: " + baseAddress);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv17ProcessRfsMessageEv",
    //     onEnter: function(arg){
    //         var name = "Nv::ProcessRfsMessage";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0])
    //         const lVar2 = arg[0].add(0x380);
    //         send(name + " lVar2: " + lVar2)
    //         const ptr2 = lVar2.readS64();
    //         send(name + " ptr2: " + ptr2.toString(16));
    //         const ptr3 = ptr2.add(4);
    //         const cmd = ptr3.readInt();
    //         send(name + "cmd: " + cmd);
    //         // var lVar2 = Memory.readS64(ptr(arg[0]).add(0x380));
    //         // send(name + " command: " + lVar2);
    //         // var cmd = Memory.readInt(ptr(lVar2).add(4));
    //         // send(name + " command: " + cmd);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN2Nv10SetIoBoostEi",
    //     onEnter: function(arg){
    //         var name = "Nv::SetIoBoost";
    //         send("[OnEnter] "  + name + " "+ "[0]: " + arg[0] + " [1]:" + arg[1]);
    //         var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
    //         for (var j in trace)
    //             send(trace[j]);
    //     },
    //     onLeave: function(ret){
            
    //     }
    // },

    {
        moduleName: "libsec-ril.so",
        funcName: "read",
        onEnter: function(arg){
            this.name = "libsec-ril-read";
            this.fd = arg[0];
            this.buffer = arg[1];
            this.size = arg[2].toInt32();
            if (this.size > 100)
                this.size = 100; // TODO avoid printing large buffer
            send("[OnEnter] " + this.name + " [0]:" + this.fd + " [1]:" + buf2hex(this.buffer) + " [2]:" + this.size);
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
        },
        onLeave: function(ret){
            var content = this.buffer.readByteArray(this.size);
            // if (this.fd.toInt32() == 23) // filter specific file descriptor
            send("[OnLeave]" + this.name + " + this.fd= "+ this.fd + " size=" + this.size + " buffer=" + buf2hex(content));
        }
    },

    {
        moduleName: "libsec-ril.so",
        funcName: "__read_chk",
        onEnter: function(arg){
            this.name = "libsec-ril-__read_chk";
            this.fd = arg[0];
            this.buffer = arg[1];
            this.size = arg[2].toInt32();
            if (this.size > 100)
                this.size = 100; // TODO avoid printing large buffer
            send("[OnEnter] " + this.name + " [0]fd:" + this.fd + + " [2]size:" + this.size + " [1]buf:" + buf2hex(this.buffer ));
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
        },
        onLeave: function(ret){
            var content = this.buffer.readByteArray(this.size);
            // if (this.fd.toInt32() == 23) // filter specific file descriptor
            send("[OnLeave]" + this.name + "\tfd=" + this.fd + "\tsize=" + this.size + "\tbuffer=" + buf2hex(content));
        }
    },
    {
        moduleName: "libsec-ril.so",
        funcName: "__write_chk", // Function name goes here
        onEnter: function(arg){
//            send('write called from:\n' +
//                Thread.backtrace(this.context, Backtracer.ACCURATE)
//                .map(DebugSymbol.fromAddress).join('\n') + '\n');
            var name = "libsec-ril-__write_chk";
            var size = arg[2].toInt32();
            var fd = arg[0];
            if(size > 100)
                size = 100
            var rawBuffer = arg[1].readByteArray(size)
            var buffer = buf2hex(rawBuffer);
            send("[OnEnter] " + name + " [0]fd:" + fd + " [2]size:" + size+ " [1]buf:" + buffer);

            if (fd.toInt32() == 23) { // filter specific file descriptor, /dev/umts_ipc0
                send("[OnEnter] " + name + " " + fd + " " + buffer);
                send(buf2str(rawBuffer));
            }
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
        },
        onLeave: function(ret){
        }
    },


    /************************** Android RIL **********************************/

//    {
//        moduleName: "libril.so",
//        funcName: "RIL_onRequestAck", // Function name goes here
//        onEnter: function(arg){
//            var name = "RIL_onRequestAck";
//            send("[OnEnter] "  + name + " "+ arg[0]);
//        },
//        onLeave: function(ret){
//        }
//    },
//
   {
       moduleName: "libril.so",
       funcName: "RIL_onRequestComplete", // Function name goes here
       onEnter: function(arg){
           var name = "RIL_onRequestComplete";
           send("[OnEnter] "  + name + " "+ arg[0]);
           var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
       },
       onLeave: function(ret){
       }
   },
//
//
//    {
//        moduleName: "libril.so",
//        funcName: "RIL_onUnsolicitedResponse", // Function name goes here
//        onEnter: function(arg){
//            var name = "RIL_onUnsolicitedResponse";
//            send("[OnEnter] "  + name + " "+ arg[0]);
//        },
//        onLeave: function(ret){
//        }
//    },


//    {
//        moduleName: "libril.so",
//        funcName: "requestToString", // Function name goes here
//        onEnter: function(arg){
//        },
//        onLeave: function(ret){
//            var name = "requestToString";
//            send(name + " " + "[onLeave] " + Memory.readCString(ret));
//        }
//    },
//
//    {
//        moduleName: "libril.so",
//        offset: 0x48168,
//        funcName: "setModemsConfig", // Function name goes here
//        onEnter: function(arg){
//            var name = "setModemsConfig";
//            send("[OnEnter] "  + name + " "+ arg[0] + " " + arg[1] + " " + arg[2]);
//        },
//        onLeave: function(ret){
//        }
//    },


//    {
//        moduleName: "libril.so",
//        funcName: "_ZN9RadioImpl4dialEiRKN7android8hardware5radio4V1_04DialE", // Function name goes here
//        onEnter: function(arg){
//            var name = "_ZN9RadioImpl4dialEiRKN7android8hardware5radio4V1_04DialE";
//            send("[OnLeave] " + name);
//        },
//        onLeave: function(ret){
//        }
//    },



    /************************** log **********************************/
   {
       moduleName: "liblog.so",
       funcName: "__android_log_buf_print", // Function name goes here
       onEnter: function(arg){
           var name = "__android_log_buf_print";
           var main_str = Memory.readCString(arg[3]);
           if (main_str.includes("Open command pipe"))
               send("[OnEnter] "  + name + " "+ main_str + " " + arg[4]);
           else if (main_str.includes("mServerSock=%d"))
               send("[OnEnter] "  + name + " "+ main_str + " " + arg[5]);
           else if (main_str.includes("%s: request id(%d), handleEvent(%d)"))
               send("[OnEnter] "  + name + " "+ main_str + " " + arg[5] + " " + arg[6]);
           else if (main_str.includes("%s: write IoChannel %d, size %d"))
               send("[OnEnter] "  + name + " "+ main_str + " " + Memory.readCString(arg[4]) + " " + arg[5] + " " + arg[6]);
           else
               send("[OnEnter] "  + name + " "+ main_str);
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
       },
       onLeave: function(ret){
       }
   },

    /************************** libc **********************************/

   {
       moduleName: "libc.so",
       funcName: "open", // Function name goes here
       onEnter: function(arg){
            var name = "open";
            var path = Memory.readCString(arg[0]);
            // if(path.includes("RFDUTINFO")){
            //     hooked = true;
            // }
            send("[OnEnter] " + name + " " + path);
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
       },
       onLeave: function(ret){
           var name = "open";
           send("[OnLeave] " + name + " " + ret);
        //    if(hooked){
        //         wait_id = ret;
        //         wait_id -= 1;
        //         send("[OnLeave] " + name + " find wait_id " + wait_id + ", ready to hook");
        //         send("[OnLeave] " + name + " find ret " + ret + ", ready to hook");
        //         wait_id += 1
        //         send("[OnLeave] " + name + " find real wait_id " + wait_id + ", ready to hook");
        //     }
       }
   },

    {
       moduleName: "libc.so",
       funcName: "__open_2", // Function name goes here
       onEnter: function(arg){
            var name = "__open_2";
            send("[OnEnter] " + name + " " + Memory.readCString(arg[0]));
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
       },
       onLeave: function(ret){
           var name = "__open_2";
           send("[OnLeave] " + name + " " + ret);
       }
   },
//
    {
        moduleName: "libc.so",
        funcName: "write", // Function name goes here
        onEnter: function(arg){
//            send('write called from:\n' +
//                Thread.backtrace(this.context, Backtracer.ACCURATE)
//                .map(DebugSymbol.fromAddress).join('\n') + '\n');
            var name = "write";
            var size = arg[2].toInt32();
            var fd = arg[0];
            if(size > 100)
                size = 100
            var rawBuffer = arg[1].readByteArray(size)
            var buffer = buf2hex(rawBuffer);
            send("[OnEnter] " + name + " fd: " + fd + " buf: " + buffer);

            if (fd.toInt32() == 23) { // filter specific file descriptor, /dev/umts_ipc0
                send("[OnEnter][write23] " + name + " fd: " + fd + " buf " + buffer);
                send(buf2str(rawBuffer));
            }
            // var temp_fd = fd;
            // temp_fd -= 1;
            // temp_fd += 1;
            // send("REPLACE: hooked " + hooked);
            // send("REPLACE: wait_id " + wait_id);
            // send("REPLACE: fd " + fd);
            // send("REPLACE: wait_id==fd " + (wait_id == temp_fd));
            // // to hook
            // if(hooked && wait_id == temp_fd){
            //     send("[OnEnter] replace Buffer");
            //     // var newData = Memory.allocUtf8String("HelloWorld");
            //     var newData = [0x48,0x65,0x6c,0x6c,0x6f];
            //     arg[1].writeByteArray(newData);

            //     var rawBuffer = arg[1].readByteArray(size)
            //     var buffer = buf2hex(rawBuffer);
            //     send("[OnEnter] hooked_" + name + " " + fd + " " + buffer);

            //     hooked = false;
            // }


            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
        },
        onLeave: function(ret){
        }
    },
//
   {
       moduleName: "libc.so",
       funcName: "read",
       onEnter: function(arg){
           var name = "libc-read";
           this.fd = arg[0];
           this.buffer = arg[1];
           this.size = arg[2].toInt32();
           if (this.size > 100)
               this.size = 100; // TODO avoid printing large buffer
            send("[OnEnter] " + name + " " + "[0]:" + arg[0] + " [1]:" + arg[1] + " [2]:" + arg[2]);
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
       },
       onLeave: function(ret){
           var content = this.buffer.readByteArray(this.size);
           if (this.fd.toInt32() == 23) // filter specific file descriptor
               send("[OnLeave] read fd=" + this.fd + "\tsize=" + this.size + "\tbuffer=" + buf2hex(content));
       }
   },

//    {
//        moduleName: "libc.so",
//        funcName: "memcpy",
//        onEnter: function(arg){
//            var name = "memcpy";
//            var ptr_src = arg[1];
//            var ptr_dst = arg[0];
//            var size = arg[2].toInt32();
//            var content = buf2hex(ptr_src.readByteArray(size));
//            send("[OnEnter] " + name + " Src:" + ptr_src + "\tDst:" + ptr_dst + "\tSize:" + size + "\t" + content);
//        },
//        onLeave: function(ret){
//        }
//    },


    {
        moduleName: "libc.so",
        funcName: "pipe",
        onEnter: function(arg){
            var name = "pipe";
            send("[OnEnter] " + name + " " + hexdump(arg[1]));
            var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
        },
        onLeave: function(ret){
        }
    },

    /************************** Vendor RIL **********************************/

    /********* AT Command *********/

    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN11MiscManager14OnAtCmdForwardEP16FactoryCmdLength",
    //     onEnter: function(arg){
    //         var moduleName = "libsec-ril.so";
    //         var name = "_ZN11MiscManager14OnAtCmdForwardEP16FactoryCmdLength";
    //         var ptr_factory_cmd_length = arg[1];
    //         var ptr_cmd_str = ptr_factory_cmd_length.add(0xE);
    //         var cmd_str = Memory.readCString(ptr_cmd_str);
    //         send("[OnEnter] " + name + " " + arg[0] + " " + cmd_str);


    //         // replace function implementation
    //         try {
    //             var oldFunc = Module.findExportByName(moduleName, name);

    //             // reserve old implementation
    //             const oldImpl = new NativeFunction(oldFunc, 'void', ['pointer', 'pointer']); // original function impl

    //             Interceptor.replace(oldFunc, new NativeCallback((arg0, arg1) => {
    //                 var cmd = Memory.readCString(arg1.add(0xE));
    //                 if (cmd.includes("ATD")) {
    //                     // block AT command ATD
    //                     send("Blocking AT command: " + cmd)
    //                     return;
    //                 }
    //                 else {
    //                     oldImpl(arg0, arg1);
    //                 }
    //             }, 'void', ['pointer', 'pointer']));

    //             send("Replacing function of " + name + " at " + oldFunc);
    //         }
    //         catch (error) {
    //             if (error["message"].includes("already replaced")) {
    //                 // send("Already replaced function " + name);
    //             }
    //             else {
    //                 send(error);
    //             }
    //         }

    //     },
    //     onLeave: function(ret){
    //     }
    // },


    /********* SMSManager *********/

//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN10SmsManager13OnIncomingSmsEP10SmsMessage9ModemType",
//         onEnter: function(arg){
//             var name = "_ZN10SmsManager13OnIncomingSmsEP10SmsMessage9ModemType";
//             var ptr_sms_message = arg[1];
//             send("[OnEnter] " + name + " " + arg[0]);
//         },
//         onLeave: function(ret){
//         }
//     },
//
//
    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN10SmsManager16OnIncomingGsmSmsEP13GsmSmsMessage",
    //     onEnter: function(arg){
    //         var name = "_ZN10SmsManager16OnIncomingGsmSmsEP13GsmSmsMessage";
    //         var ptr_sms_message = arg[1];
    //         send("[OnEnter] " + name + " " + ptr_sms_message);
    //     },
    //     onLeave: function(ret){
    //     }
    // },
//
//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN13GsmSmsMessage8ToStringEv",
//         onEnter: function(arg){
//         },
//         onLeave: function(ret){
//             var name = "_ZN13GsmSmsMessage8ToStringEv";
//             send("[OnLeave] " + name + Memory.readCString(ret));
//         }
//     },
//
//
//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN3Pdu11ToHexStringEv",
//         onEnter: function(arg){
//         },
//         onLeave: function(ret){
//             var name = "_ZN3Pdu11ToHexStringEv";
//             send("[OnLeave] " + name + " " + Memory.readCString(ret));
//         }
//     },
//
//
// //    {
// //        moduleName: "libsec-ril.so",
// //        funcName: "_ZN9SmsCenter11GetDigitStrEv",
// //        onEnter: function(arg){
// //        },
// //        onLeave: function(ret){
// //            var name = "_ZN9SmsCenter11GetDigitStrEv";
// //            send("[OnLeave] " + name + " " + Memory.readCString(ret));
// //        }
// //    },
//
//
//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN10SmsManager9DoSendSmsEP7Requesti9ModemType",
//         onEnter: function(arg){
//             var name = "_ZN10SmsManager9DoSendSmsEP7Requesti9ModemType";
//             send("[OnEnter] " + name + " " + arg[0]);
//
//             // intercept SMS here
//             // replace function implementation
// //            var oldFunc = Module.findExportByName("libsec-ril.so", name);
// //            send("Replacing function of " + name + " at " + oldFunc);
// //
// //            const oldImpl = new NativeFunction(oldFunc, 'int', ['pointer', 'pointer', 'int', 'int']); // original function impl
// //
// //            Interceptor.replace(oldFunc, new NativeCallback((arg0, arg1) => {
// //                return 1;
// //            }, 'int', ['pointer', 'pointer', 'int', 'int']));
//
//         },
//         onLeave: function(ret){
//         }
//     },
//
//
//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN13GsmSmsMessage5ParseEb",
//         onEnter: function(arg){
//             var name = "_ZN13GsmSmsMessage5ParseEb";
// //            send(hexdump(arg[0].add(0x18).readPointer())); // pdu content
//             this.ptr_sms_message = arg[0];
//         },
//         onLeave: function(ret){
//             // simulate silent SMS
//             // set protocol id to be 64
// //            this.ptr_sms_message.add(0x44).writeInt(64); // 64 is the id of silent sms
// //
// //            // set class
// //            this.ptr_sms_message.add(0x58).writeInt(3); // 3 means class 2
// //
// //            // set format
// //            this.ptr_sms_message.add(0x28).writeInt(1); // 1 means normal type?
// //
//
//             // simulate SIM Jacker SMS
//             // set protocol id to be 0x7f
// //            this.ptr_sms_message.add(0x44).writeInt(0x7f); // 64 is the id of silent sms
// //
// //            // set DCS
// //            this.ptr_sms_message.add(0x50).writeInt(0xf6);
// //
// //            // set class
// //            this.ptr_sms_message.add(0x58).writeInt(3); // 3 means class 2
// //
// //            // set modem type?
// //            this.ptr_sms_message.add(0x24).writeInt(8);
//
// //            arg[0].add(0x4c).writeInt(2);
//
//
//             if (this.ptr_sms_message.add(0x44).readInt() == 0x40) {
//                 // silent SMS detected
//                 send("Silent SMS detected!!!!!!!!!!!!!");
//             }
//             else if (this.ptr_sms_message.add(0x44).readInt() == 0x7f) {
//                 // silent SMS detected
//                 send("Binary SMS detected!!!!!!!!!!!!!");
//             }
//
//             var name = "_ZN13GsmSmsMessage5ParseEb";
//             send("[OnLeave] " + name + " " + this.ptr_sms_message);
//         }
//     },


//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN13GsmSmsMessage22IsShortMessageType0MsgEv",
//        onEnter: function(arg){
//        },
//        onLeave: function(ret){
//            var name = "_ZN13GsmSmsMessage22IsShortMessageType0MsgEv";
//            send("[OnLeave] " + name + ret);
//        }
//    },

//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN6Region9IsNtcMainEPKc",
//        onEnter: function(arg){
//        },
//        onLeave: function(ret){
//            var name = "_ZN6Region9IsNtcMainEPKc";
//            ret.replace(1);
//            send("[OnLeave] " + name + ret);
//        }
//    },

//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN3PduC1EPci",
//         onEnter: function(arg){
//             var name = "_ZN3PduC1EPci";
//             // simulate SIM Jacker message
// //            arg[1].add(0x9).writeInt(0x7f); // set PID
// //            arg[1].add(0xa).writeInt(0xf6); // set DCS
//
//             send("[OnEnter] " + name + "\n" + hexdump(arg[1]));
//         },
//         onLeave: function(ret){
//         }
//     },


//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN13IpcProtocol4119IpcTxDeliveryReportEiiii",
//        onEnter: function(arg){
//            var name = "_ZN13IpcProtocol4119IpcTxDeliveryReportEiiii";
//            var tpid = arg[2];
//            var result = arg[3];
//            var reason = arg[4];
//            send("[OnEnter] " + name + " " + arg[0] + " " + tpid + " " + result + " " + reason);
//        },
//        onLeave: function(ret){
//        }
//    },


    // {
    //     moduleName: "libsec-ril.so",
    //     funcName: "_ZN10SmsManager11HandleEventER7Message",
    //     onEnter: function(arg){
    //         var name = "_ZN10SmsManager11HandleEventER7Message";
    //         var req_id = arg[1].add(0x24).readInt();
    //         send("[OnEnter] " + name + " " + arg[0] + " req_id=" + req_id);
    //     },
    //     onLeave: function(ret){
    //     }
    // },


    /********* GPS *********/

//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN11MiscManager21DoOemGetApGpsPositionEP7Request",
//        onEnter: function(arg){
//            var name = "_ZN11MiscManager21DoOemGetApGpsPositionEP7Request";
//            var ptr_request = arg[1];
//            send("[OnEnter] " + name + " " + arg[0] + " " + ptr_request);
//        },
//        onLeave: function(ret){
//        }
//    },
//
//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN14GsmMiscManager11HandleEventER7Message",
//        onEnter: function(arg){
//            var name = "_ZN14GsmMiscManager11HandleEventER7Message";
//            var req_id = arg[1].add(0x24).readInt().toString(16);
//            send("[OnEnter] " + name + " " + arg[0] + " req_id = 0x" + req_id);
//        },
//        onLeave: function(ret){
//        }
//    },

    /**
        Struct Request {
            0x10: int id
            0x14: int
            0x18: ReqType*
            0x38: RilData*
            0x40: void*
        }
    **/

//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN11MiscManager9DoOemMiscEP7Request",
//         onEnter: function(arg){
//             var name = "_ZN11MiscManager9DoOemMiscEP7Request";
//             var sub_req_id = arg[1].add(0x38).readPointer().add(0xd).readU8();
// //            if (sub_req_id == 0x98) {
// //                // replace 0x98 to 0x72 (gps)
// //                send("Rewriting sub_req_id from 0x98 to 0x72 to invoke GPS function");
// //                arg[1].add(0x38).readPointer().add(0xd).writeU8(0x72);
// //            }
//             send("[OnEnter] " + name + " " + arg[0] + " sub_req_id = 0x" + sub_req_id.toString(16));
//         },
//         onLeave: function(ret){
//         }
//     },

//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN11RespDataRawC2EPvi",
//         onEnter: function(arg){
//             var name = "_ZN11RespDataRawC2EPvi";
//             var length = arg[2].toInt32();
//             var resp_byte_array = arg[1];

//             this.ptr = arg[0];
//             //.readByteArray(length);
// //            send("[OnEnter] _ZN11RespDataRawC2EPvi " + resp_byte_array + " " + length + hexdump(this.ptr));
// //            send("[OnEnter] " + name + " " + length + " " + arg[0] + " resp = " + bytesToHex(resp_byte_array));
//         },
//         onLeave: function(ret){
//             send("[OnLeave] _ZN11RespDataRawC2EPvi " + hexdump(this.ptr));
//             send("[OnLeave] _ZN11RespDataRawC2EPvi " + hexdump(this.ptr.add(0x10).readPointer()));
//         }
//     },


//     {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN13IpcProtocol4117GetSubCommandNameEii",
//        onEnter: function(arg){
//        },
//        onLeave: function(ret){
//            send("[OnLeave] _ZN13IpcProtocol4117GetSubCommandNameEii " + Memory.readCString(ret));
//        }
//    },


//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN13IpcProtocol4122IpcRxApGpsPositionRespEPciRiR14RegistrantType",
//        onEnter: function(arg){
//            var name = "_ZN13IpcProtocol4122IpcRxApGpsPositionRespEPciRiR14RegistrantType";
//            send("[OnEnter] " + name + "\n" + hexdump(arg[0]) + "\n" + hexdump(arg[1]) + " " +  arg[2] + " " + Memory.readInt(arg[3]) + " " + arg[4]);
//        },
//        onLeave: function(ret){
//        }
//    },



    /********* NetworkManager *********/

//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN14NetworkManager11HandleEventER7Message",
//         onEnter: function(arg){
//             var name = "_ZN14NetworkManager11HandleEventER7Message";
//             var req_id = arg[1].add(0x24).readInt();
//             send("[OnEnter] " + name + " " + arg[0] + " req_id = 0x" + req_id.toString(16));

// //            if (req_id == 0xc9) { // 201
// //                send("Replacing req_id from 0xc9 to 0xa7 to trigger disable 2g");
// //                arg[1].add(0x24).writeInt(0xa7);
// //            }
//         },
//         onLeave: function(ret){
//         }
//     },


//    {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN14NetworkManager14DoSetDisable2gEP7Request",
//         onEnter: function(arg){
//             var name = "_ZN14NetworkManager14DoSetDisable2gEP7Request";

//             if (arg[1].add(0x38).readPointer().add(0xc).readInt() == 0) {
//                 send("replacing 0 to 1");
//                 arg[1].add(0x38).readPointer().add(0xc).writeInt(1);
//             }

//             send("[OnEnter] " + name + " " + arg[1]);
//         },
//         onLeave: function(ret){
//         }
//     },


//     {
//         moduleName: "libsec-ril.so",
//         funcName: "_ZN13IpcProtocol4117IpcTxSetDisable2gEb",
//         onEnter: function(arg){
//             var name = "_ZN13IpcProtocol4117IpcTxSetDisable2gEb";
//             send("[OnEnter] " + name + " " + arg[1]);
//         },
//         onLeave: function(ret){
//         }
//     },


    /********* CallManager *********/

//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN11CallManager16DoSetImsCallListEP7Request",
//        onEnter: function(arg){
//            var name = "_ZN11CallManager16DoSetImsCallListEP7Request";
//            var moduleName = "libsec-ril.so";
//            send("[OnEnter] " + name);
//
//            var oldFunc = Module.findExportByName(moduleName, name);
//
//            // replace native function implementation
//            send("Replacing function of " + name + " at " + oldFunc);
//
//            const oldImpl = new NativeFunction(oldFunc, 'int', ['pointer', 'pointer']); // original function impl
//
//            Interceptor.replace(oldFunc, new NativeCallback((arg0, arg1) => {
//                return 1;
//            }, 'int', ['pointer', 'pointer']));
//        },
//        onLeave: function(ret){
//        }
//    },

//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN13IpcProtocol4123IpcTxImsCallSetCallListEP11ImsCallList",
//        onEnter: function(arg){
//            var name = "_ZN13IpcProtocol4123IpcTxImsCallSetCallListEP11ImsCallList";
//            var moduleName = "libsec-ril.so";
//            send("[OnEnter] " + name);
//
//            var oldFunc = Module.findExportByName(moduleName, name);
//
//            // replace native function implementation
//            send("Replacing function of " + name + " at " + oldFunc);
//
//            const oldImpl = new NativeFunction(oldFunc, 'int', ['pointer', 'pointer']); // original function impl
//
//            Interceptor.replace(oldFunc, new NativeCallback((arg0, arg1) => {
//                return 1;
//            }, 'int', ['pointer', 'pointer']));
//        },
//        onLeave: function(ret){
//        }
//    },


    /********* Others *********/

   {
       moduleName: "libsec-ril.so",
       funcName: "OnRequest",
       onEnter: function(arg){
           var name = "OnRequest";
           send("[OnEnter] " + name + " " + arg[0] + " " + Memory.readCString(arg[1]) + " " + arg[2]);
           var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
            for (var j in trace)
                send(trace[j]);
       },
       onLeave: function(ret){
       }
   },

//
//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN11SecRilProxy9OnRequestEiPciPv7ReqType",
//        onEnter: function(arg){
//            var name = "_ZN11SecRilProxy9OnRequestEiPciPv7ReqType";
//            send("[OnEnter] " + name + " " + arg[0] + " ");
// //            send("[OnEnter] " + name + " " + arg[0] + " " + bytesToHex(Memory.readCString(arg[1])) + " " + arg[2]);
//             var trace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress);
//             for (var j in trace)
//                 send(trace[j]);
//        },
//        onLeave: function(ret){
//        }
//    },


//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN13AsyncReceiver6NotifyEPci",
//        onEnter: function(arg){
//            var name = "_ZN13AsyncReceiver6NotifyEPci";
////            send(arg[0].add(0xc).readInt()); // fd
//            send("[OnEnter] " + name + " " + buf2hex(arg[1].readByteArray(arg[2].toInt32())) + " " + arg[2]);
//        },
//        onLeave: function(ret){
//            // read from pipe 52572 (0xa) --> AsyncReceiver::Notify() --> ReqDispatcherAsyncReceiver::OnReceive()
//        }
//    },


//    {
//        moduleName: "libsec-ril.so",
//        funcName: "_ZN26ReqDispatcherAsyncReceiver9OnReceiveEPci",
//        onEnter: function(arg){
//            var name = "_ZN26ReqDispatcherAsyncReceiver9OnReceiveEPci";
//            send("[OnEnter] " + name + " " + buf2hex(arg[1].readByteArray(arg[2].toInt32())) + " " + arg[2]);
//        },
//        onLeave: function(ret){
//        }
//    },

]


// // enumerate modules and functions
// Process.enumerateModules({
//     onMatch: function(module) {
// //        send(module.name);
//         if (target_module_name.includes(module.name)) {
//             // module find
//             send("[ModuleOnMatch] find " + module.name + " " + module.base + " " + module.size + " " + module.path);

//             // enable log
//             var log_var_offset = 0x004de504-0x00100000
//             var log_bit = Memory.readInt(module.base.add(log_var_offset));
//             if (log_bit <= 1) {
//                 send("Enabling log by rewriting " + module.base.add(log_var_offset) + " from " + log_bit + " to 5");
//                 module.base.add(log_var_offset).writeInt(5);
//             }

//             var exports = module.enumerateExports();
//             for (var i=0; i<exports.length; ++i) {
//                 if (exports[i].name.includes("IpcRx") || exports[i].name.includes("IoChannel") || exports[i].name.includes("IpcModem") || exports[i].name.includes("IpcHijacker") || exports[i].name.includes("IpcProtocol41")) {
//                     var templateFuncHook = createHookFunctionTemplate(exports[i].name, module.name);
//                     hookFunctions.push(templateFuncHook);
// //                    send(exports[i].name);
//                 }
//             }
//         }

// //        var exports = module.enumerateExports();
// //        for (var i=0; i<exports.length; ++i) {
// //            if (exports[i].name.includes("getEnableStatus")) {
// //                send(exports[i].name);
// //                send(module.name);
// //            }
// //        }
//     },

//     onComplete: function() {
//         send("[ModuleOnComplete]");
//     }
// });



// place hooks
for(var i = 0; i < hookFunctions.length; i++){
    hookFunction(hookFunctions[i]);
}


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
        send("Placing function hook on: " + fName + " at " + exp);
    }
    else {
        send("Unable to locate function " + fName + " from module " + moduleName);
        return;
    }

    try {
        Interceptor.attach(exp, {
            onEnter: hookFunc.onEnter,
            onLeave: hookFunc.onLeave
        });
    }
    catch (error) {
        send(error);
    }
}



function createHookFunctionTemplate(funcName, moduleName) {

    if (funcName.includes("HandleEvent")) {
        // handle event function template
        return {
            moduleName: moduleName,
            funcName: funcName,
            onEnter: function(arg){
                send("[OnEnter] " + funcName + " message id = " + arg[1].add(0x24).readInt());
            },
            onLeave: function(ret){

            }
        };
    }
    else {
        // rest
        return {
            moduleName: moduleName,
            funcName: funcName,
            onEnter: function(arg){
                send("[OnEnter] " + funcName + " "  + arg[0]);
            },
            onLeave: function(ret){

            }
        };
    }
}


function hookFunctionWithOffset(hookFunc) {
    var base = Module.findBaseAddress(hookFunc.moduleName);

    // intercepting function
    send("Placing function hook on: " + hookFunc.funcName + " at " + base.add(hookFunc.offset));

    Interceptor.attach(base.add(hookFunc.offset), {
        onEnter: hookFunc.onEnter,
        onLeave: hookFunc.onLeave
    });
}


function replaceFunction(hookFunc, retType, argTypeList, newImpl) {

    var oldFunc = null;
    if (hookFunc.offset)
        oldFunc = base.add(hookFunc.offset);
    else
        oldFunc = Module.findExportByName(hookFunc.moduleName, hookFunc.funcName);

    // replace native function implementation
    send("Replacing function of " + hookFunc.funcName + " at " + oldFunc);

    Interceptor.replace(oldFunc, newImpl);


//    const oldImpl = new NativeFunction(oldFunc, 'int', ['int', 'int', 'pointer']); // original function impl
//    Interceptor.replace(oldFunc, new NativeCallback((arg0, arg1, arg2) => {
//
//    }, 'int', ['int', 'int', 'pointer']));
}



function buf2hex(buffer) { // buffer is an ArrayBuffer
  return [...new Uint8Array(buffer)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join(' ');
}


function buf2str(buffer) {
    send(buffer);
    return String.fromCharCode.apply(null, new Uint8Array(buffer));
}


function print_native_call_stack(f) {
    Interceptor.attach(f, {
      onEnter: function (args) {
        send(f + ' called from:\n' +
            Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n') + '\n');
      }
    });
}
