
Java.perform(function () {
//   var act = Java.use("android.app.Activity");
//   act.getIntent.overload().implementation = function () {
//     var intent = this.getIntent()
//     var cp = intent.getComponent()
//     console.log("Starting " + cp.getPackageName() + "/" + cp.getClassName())
//     var ext = intent.getExtras();
//     if (ext) {
//       var keys = ext.keySet()
//       var iterator = keys.iterator()
//       while (iterator.hasNext()) {
//         var k = iterator.next().toString()
//         var v = ext.get(k)
//         if (v != null && k != null) {
//            console.log("\t" + v.getClass().getName())
//            console.log("\t" + k + ' : ' + v.toString())
//         }
//       }
//     }
//   return intent;
//   };


   var SmsManager = Java.use('android.telephony.SmsManager');
   var sendTextMessage = SmsManager.sendTextMessage;
   var JavaString = Java.use('java.lang.String');
   var PendingIntent = Java.use('android.app.PendingIntent');

   SmsManager.sendTextMessage.overloads[0].implementation = function(dest) {
            console.log("sendTextMessage for " + dest);
            return this.sendTextMessage.overloads[0].apply(this, arguments);
   };

//   sendTextMessage.overload(JavaString, JavaString, JavaString, PendingIntent, PendingIntent).
//   sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent').
//   implementation = function(arg0, arg1, arg2, arg3, arg4) {
//        send("SmsManager.sendTextMessage");
//        return this.sendTextMessage(arg0, arg1, arg2, arg3, arg4);
//   }



//    var RILSender = Java.use('com.android.internal.telephony.RIL.RILSender');
//    var handleMessage = RILSender.handleMessage.overloads[0];
//
//    handleMessage.implementation = function(dest) {
//        send("RILSender.handleMessage");
//        return this.handleMessage.overloads[0].apply(this.arguments);
//    }

    var Binder = Java.use("android.os.Binder");
    var getCallingPid = function () {
        console.log("Caller's PID: " + Binder.getCallingPid());
    }

    var GSMDispatcher = Java.use("com.android.internal.telephony.gsm.GsmSMSDispatcher");
    GSMDispatcher.sendSms.overloads[0].implementation = function (dest) {
        console.log("GSMDispatcher.sendSMS " + dest);
        printBacktrace();
        getCallingPid();
        return this.sendSms.overloads[0].apply(this, arguments);
    }


    var printBacktrace = function () {
        Java.perform(function() {
            var JLog = Java.use('android.util.Log'), JException = Java.use('java.lang.Exception');
            // getting stacktrace by throwing an exception
            console.log(JLog.getStackTraceString(JException.$new()));
        });
    };
})

