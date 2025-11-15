function FindProxyForURL(url, host) {

    // --- Helper: send to WireGuard ---
    function PROXY() {
        return "PROXY 192.168.50.135:7897"; // твой Clash listen
    }

    // --- Helper: direct ---
    function DIRECT_CONN() {
        return "DIRECT";
    }

    host = host.toLowerCase();
    url = url.toLowerCase();

    // ===========
    //  CHATGPT / OPENAI
    // ===========
    if (dnsDomainIs(host, "openai.com") ||
        dnsDomainIs(host, "chatgpt.com") ||
        dnsDomainIs(host, "ai.com") ||
        dnsDomainIs(host, "oaiusercontent.com") ||
        dnsDomainIs(host, "cdn.openai.com") ||
        shExpMatch(host, "*.openai.com") ||
        shExpMatch(host, "*.chatgpt.com")) {
        return PROXY();
    }

    // ===========
    //  META / INSTAGRAM / FACEBOOK / OCULUS
    // ===========
    if (
        shExpMatch(host, "*.instagram.com") ||
        shExpMatch(host, "*.cdninstagram.com") ||
        shExpMatch(host, "*.fbcdn.net") ||
        shExpMatch(host, "*.facebook.com") ||
        shExpMatch(host, "*.facebook.net") ||
        shExpMatch(host, "*.fb.com") ||
        shExpMatch(host, "*.tfbnw.net") ||
        shExpMatch(host, "*.c10r.facebook.com") ||
        shExpMatch(host, "*.scontent.xx.fbcdn.net") ||
        shExpMatch(host, "*.edge-chat.facebook.com") ||
        shExpMatch(host, "*.i.instagram.com") ||
        shExpMatch(host, "*.graph.instagram.com")
    ) {
        return PROXY();
    }

    // ===========
    //  DISCORD (iOS)
    // ===========
    if (
        shExpMatch(host, "*.discord.com") ||
        shExpMatch(host, "*.discord.gg") ||
        shExpMatch(host, "*.discordapp.com") ||
        shExpMatch(host, "*.discord-media.com") ||
        shExpMatch(host, "*.discordcdn.com")
    ) {
        return PROXY();
    }

    // ===========
    //  PROTON
    // ===========
    if (
        shExpMatch(host, "*.proton.me") ||
        shExpMatch(host, "*.protonmail.com") ||
        shExpMatch(host, "*.protonvpn.com")
    ) {
        return PROXY();
    }

    // ===========
    //  ADULT BLOCKED SITES
    // ===========
    if (
        shExpMatch(host, "*.hanime.tv") ||
        shExpMatch(host, "*.hentaihaven.xxx") ||
        shExpMatch(host, "*.pornhub.com") ||
        shExpMatch(host, "*.phncdn.com") ||
        shExpMatch(host, "*.xvideos.com") ||
        shExpMatch(host, "*.xnxx.com") ||
        shExpMatch(host, "*.eporner.com") ||
        shExpMatch(host, "*.redtube.com") ||
        url.indexOf("hentai") !== -1 ||
        url.indexOf("porn") !== -1
    ) {
        return PROXY();
    }

    // ===========
    //  TORRENTS
    // ===========
    if (
        url.indexOf("torrent") !== -1 ||
        url.indexOf("magnet:") !== -1 ||
        shExpMatch(host, "*.rutracker.org") ||
        shExpMatch(host, "*.1337x.to") ||
        shExpMatch(host, "*.tfile.me") ||
        shExpMatch(host, "*.rarbg.to") ||
        shExpMatch(host, "*.torrentgalaxy.to") ||
        shExpMatch(host, "*.nyaa.si")
    ) {
        return PROXY();
    }

    // ===========
    //  RADARR / SONARR
    // ===========
    if (
        shExpMatch(host, "*.radarr.video") ||
        shExpMatch(host, "*.sonarr.tv") ||
        shExpMatch(host, "*.lidarr.audio") ||
        shExpMatch(host, "*.jackett.dev") ||
        shExpMatch(host, "*.flaresolverr") ||
        shExpMatch(host, "*.themoviedb.org") ||
        shExpMatch(host, "*.tvdb.com")
    ) {
        return PROXY();
    }

    // ===========
    // VDSINA
    // ===========
    if (
        shExpMatch(host, "*.vdsina.ru") ||
        shExpMatch(host, "*.vdsina.com")
    ) {
        return PROXY();
    }

    // ===========
    // DEFAULT RULE (everything else goes direct)
    // ===========
    return DIRECT_CONN();
}
