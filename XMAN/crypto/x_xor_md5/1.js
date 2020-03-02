function stoh(t) {
    return t.split("").map(function(t) {
        return t.charCodeAt(0)
    })
}
function htos(t) {
    return String.fromCharCode.apply(String, t)
}
function getBase64Image(t) {
    var e = document.getElementById(t),
    a = document.createElement("canvas");
    a.width = e.width,
    a.height = e.height;
    var n = a.getContext("2d");
    n.drawImage(e, 0, 0);
    var r = a.toDataURL("image/png");
    return r.replace(/^data:image\/(png|jpeg);base64,/, "")
}