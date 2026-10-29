// ---- Needs approval? ----
// Runs after the alert message was sent. Only alerts whose action is possible and whose severity
// reaches APPROVAL_FROM go on to the response workflow; everything else ends here.
const f = $('Build message').first().json;
return f.action?.offer === true ? [{ json: f }] : [];
