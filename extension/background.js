// Adds "Check with Second Look" to the right-click menu for selected text.
// The text goes in the URL fragment (#t=...), which browsers never send to the server.
const APP = 'https://second-look-kronides.web.app/';
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: 'second-look', title: 'Check with Second Look', contexts: ['selection'] });
});
chrome.contextMenus.onClicked.addListener((info) => {
  if (info.menuItemId !== 'second-look' || !info.selectionText) return;
  const text = info.selectionText.slice(0, 6000);
  chrome.tabs.create({ url: `${APP}#t=${encodeURIComponent(text)}` });
});
