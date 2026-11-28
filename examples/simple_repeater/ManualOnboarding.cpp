#include "MyMesh.h"

void MyMesh::handleOnboardingCommand(const char* command, char* reply, bool usb, bool canWrite) {
  const auto* subnet = _rules.scopeName(RuleStore::Subnet);
  if (!*command) {
    const char* state = !*subnet ? "unmanaged" : _rules.onboarding() ? "pending" : "active";
    snprintf(reply, 150, "subnet=%s onboarding=%s transit=%s", *subnet ? subnet : "none", state,
             _rules.transitAllowed() && !_prefs.disable_fwd ? "available" : "held");
    return;
  }
  if (!canWrite) { strcpy(reply, "Err - admin permission required"); return; }
  if (handlePeerOnboardingCommand(command, reply)) return;
  if (savemesh::matchesValue(command, "start")) {
    const bool pending = _rules.onboarding();
    if (!usb || !_rules.startOnboarding()) {
      strcpy(reply, "Err - use rules onboarding start over USB with a configured subnet");
      return;
    }
    if (!pending) clearOutboundQueue();
    _onboarding_review_revision = 0;
    clearPeerOnboarding();
    strcpy(reply, "OK - onboarding pending; transit held");
    return;
  }
  if (!_rules.onboarding() || !_rules.forwardingAllowed()) {
    strcpy(reply, "Err - no readable onboarding policy pending");
    return;
  }
  if (peerOnboardingBusy()) { strcpy(reply, "Err - peer onboarding transfer pending"); return; }
  const uint8_t options = uint8_t(_filter_prefs.filter_1byte)
                        | uint8_t(_filter_prefs.filter_data << 1)
                        | uint8_t(_filter_prefs.filter_public << 2)
                        | uint8_t(_prefs.disable_fwd ? 8 : 0);
  const uint32_t revision = _rules.revision();
  char token[11];
  snprintf(token, sizeof(token), "%08lx%02x", static_cast<unsigned long>(revision), options);
  if (savemesh::matchesValue(command, "review")) {
    _onboarding_review_revision = revision;
    _onboarding_review_options = options;
    snprintf(reply, 150, "review=%s subnet=%s mode=%s filters=%u/%u/%u repeat=%s",
             token, subnet, _rules.modeName(), _filter_prefs.filter_1byte, _filter_prefs.filter_data,
             _filter_prefs.filter_public, _prefs.disable_fwd ? "off" : "on");
    return;
  }
  const char* supplied;
  if (!savemesh::matchCommand(command, "commit", &supplied)) {
    strcpy(reply, "Err - use onboarding start, review or commit <review>");
    return;
  }
  if (_onboarding_review_revision != revision || _onboarding_review_options != options
      || !savemesh::matchesValue(supplied, token)) {
    strcpy(reply, "Err - policy changed; run rules onboarding review");
    return;
  }
  if (!_rules.commitOnboarding(revision)) {
    strcpy(reply, "Err - onboarding commit failed; transit held");
    return;
  }
  _onboarding_review_revision = 0;
  snprintf(reply, 150, "OK - committed rev=%lu transit=%s", static_cast<unsigned long>(_rules.revision()),
           _prefs.disable_fwd ? "held" : "available");
}
