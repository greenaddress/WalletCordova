// Copyright 2014 Mike Tsao <mike@sowbug.com>

// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy,
// modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

'use strict';

function Electrum($http, $q) {
  this.SERVERS = [
    "http://b.1209k.com/",
    "http://ecdsa.net:8081/",
    "http://electrum.hachre.de:8081/",
    "http://electrum.coinwallet.me:8081/",
    "http://bitcoin.epicinet.net:8081/",
    "http://electrum.electricnewyear.net:8081/",
    "http://cube.l0g.in:8081/",
    "http://electrum.be:8081/",
    "http://electrum.novit.ro:8081/",
    "http://electrum.stepkrav.pw:8081/",
    "http://e.slush.cz:8081/"
  ];
  this.callbacks = {};
  this.callbackId = 1;
  this.rpcQueue = [];

  this.issueAddressGetHistory = function(addr_b58) {
    return this._enqueueRpc("blockchain.address.get_history", [addr_b58]);
  };

  this.issueAddressSubscribe = function(addr_b58) {
    return this._enqueueRpc("blockchain.address.subscribe", [addr_b58]);
  };

  this.issueTransactionGet = function(tx_hash) {
    return this._enqueueRpc("blockchain.transaction.get", [tx_hash]);
  };

  this.issueTransactionBroadcast = function(tx) {
    return this._enqueueRpc("blockchain.transaction.broadcast", [tx]);
  };

  this.issueHeadersSubscribe = function() {
    return this._enqueueRpc("blockchain.headers.subscribe", []);
  };

  this.issueBlockGetHeader = function(block_num) {
    return this._enqueueRpc("blockchain.block.get_header", [block_num]);
  };

  // TODO(miket): there's just no way this will work
  this.pendingRpcCount = 0;

  this.resetTimeoutDuration = function() {
    this.timeoutDuration = 128;
  };

  this.areRequestsPending = function() {
    return this.pendingRpcCount > 0;
  };

  this.advanceTimeoutDuration = function() {
    if (!this.timeoutDuration) {
      this.resetTimeoutDuration();
    } else {
      if (this.timeoutDuration < 120 * 1000) {
        this.timeoutDuration *= 2;
      } else {
        window.CustomNativeAccess.clearCookies();  // reset session every ~2 minutes
      }
    }
  };

  this.scheduleNextConnect = function() {
    if (this.nextConnectTimeoutId) {
      window.clearTimeout(this.nextConnectTimeoutId);
    }
    this.nextConnectTimeoutId = window.setTimeout(this.connect.bind(this),
                                                  this.timeoutDuration);
    this.advanceTimeoutDuration();
  };

  this._enqueueRpc = function(method, params) {
    var deferred = $q.defer();
    
    var rpc = { "id": this.callbackId++,
                "method": method,
                "params": params,
              };
    this.rpcQueue.push(rpc);
    this.callbacks[rpc.id] = {'resolve': deferred.resolve, 'reject': deferred.reject};
    this.pendingRpcCount++;
    this.resetTimeoutDuration();
    this.scheduleNextConnect();
    
    return deferred.promise;
  };

  this.pickRandomServer = function() {
    var newUrl;
    do {
      newUrl =
        this.SERVERS[Math.floor(Math.random() * this.SERVERS.length)];
    } while (newUrl == this.currentServerUrl);
    this.currentServerUrl = newUrl;
  };

  // Old session cookies can cause 'session not found' errors
  window.CustomNativeAccess.clearCookies();
  this.pickRandomServer();

  this.connect = function() {
    var obj = undefined;
    if (this.rpcQueue.length) {
      obj = this.rpcQueue.shift();
      // TODO(miket): can probably push whole thing
    }

    var handleResponse = function(o) {
      var id = o.id;
      if (this.callbacks[id]) {
        this.callbacks[id].resolve(o.result);
        delete this.callbacks[id];
        this.pendingRpcCount--;
      }
    };

    var success = function(data, status, headers, config) {
      if (data && !data.error) {
        this.resetTimeoutDuration();
        if (data instanceof Array) {
          for (var o in data) {
            handleResponse.call(this, data[o]);
          }
        } else {
          handleResponse.call(this, data);
        }
      }
      this.scheduleNextConnect();
    };
    var error = function(data, status, headers, config) {
      console.log("Electrum error", status, data);
      if (obj) {
        this.pickRandomServer();
        this.rpcQueue.unshift(obj);  // retry
      }
      this.scheduleNextConnect();
    };

    if (obj) {
      $http.post(this.currentServerUrl, obj, { withCredentials: true, no_loading_indicator: true }).
        success(success.bind(this)).
        error(error.bind(this));
    } else {
      $http.get(this.currentServerUrl, { withCredentials: true, no_loading_indicator: true }).
        success(success.bind(this)).
        error(error.bind(this));
    }
  };
}