var target_module_name = ["libsec-ril.so", "libsec-ril-dsds.so"];

var hookFunctions = [
    {
        moduleName: "libsec-ril.so",
        funcName: "_ZN11SecRilProxy17OnRequestCompleteEP7RequestiP7RilData",
        onEnter: function(arg){
            var name = "SecRilProxy::OnRequestComplete";
            send(name + " " + "[OnEnter] " + "[1]:" + arg[1] + " [2] " + arg[2] + "[3]" + arg[3]);
        },
        onLeave: function(ret){

        }
    }
]