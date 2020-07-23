(function (open) {
    XMLHttpRequest.prototype.open = function (method, url, async, user, password) {
        url = new URL(url, window.location.href.split('/browser/').slice(1).join('/browser/')).href;
        open.call(this, method, '/browser/' + url, async, user, password);
    };
})(XMLHttpRequest.prototype.open);
