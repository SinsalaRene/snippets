// Needs to be on a page where the Playlist is currently playing.
// Closing the page will stop the execution/ intervall function
// Alternatively call: clearInterval()
setInterval(function () { var el = document.querySelectorAll('[aria-label="Delete"]');; el[0].click(); }, 1000)