(function (open) {
    XMLHttpRequest.prototype.open = function (method, url, async, user, password) {
        open.call(this, method, '/browser/' + url, async, user, password);
    };
})(XMLHttpRequest.prototype.open);
