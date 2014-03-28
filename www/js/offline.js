var app = {
    // Application Constructor
    initialize: function() {
        this.bindEvents();
    },
    // Bind Event Listeners
    //
    // Bind any events that are required on startup. Common events are:
    // 'load', 'deviceready', 'offline', and 'online'.
    bindEvents: function() {
        document.addEventListener("offline", this.onDeviceOffline, false);
        document.addEventListener("online", this.onDeviceOnLine, false);
        document.addEventListener('deviceready', this.onDeviceReady, false);
    },

    onDeviceOnLine: function() {
        console.log("Device online");
        //if (window.location.href != destination) {
        //    window.location.href = destination;
        //}
        plugins.appPreferences.fetch(function(language) {
            window.location.href = destination.replace('/en/', '/'+language+'/');
        }, function(error) {
            window.location.href = destination;
        }, 'language');
    },

    onDeviceOffline: function() {
        console.log("Device offline");
        app.receivedEvent('deviceready');
        //if (window.location.href != destination) {
        //    app.receivedEvent('deviceready');
        //}
    },

    onDeviceResume: function() {
        console.log("Device resuming");
    },
    // deviceready Event Handler
    //
    // The scope of 'this' is the event. In order to call the 'receivedEvent'
    // function, we must explicity call 'app.receivedEvent(...);'
    onDeviceReady: function() {
        //app.receivedEvent('deviceready');
        console.log("Device ready");
        console.log(navigator.userAgent);
        console.log(window.location.href);
    },

    // Update DOM on a Received Event
    receivedEvent: function(id) {
        var parentElement = document.getElementById(id);
        var listeningElement = parentElement.querySelector('.listening');
        var receivedElement = parentElement.querySelector('.received');

        listeningElement.setAttribute('style', 'display:none;');
        receivedElement.setAttribute('style', 'display:block;');

        console.log('Received Event: ' + id);
    }
};
