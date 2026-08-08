# maildancer system default filtering.
#
# Applied to a delivery only when the recipient has no .sieve of their own. A
# user script REPLACES this one rather than layering under it: writing your own
# rules means you own the policy, including the decision to leave flagged mail
# in the inbox.
#
# Install by copying to the root of the mail DATA tree (the directory named by
# domains_data_path), as system.sieve, mode 0644:
#
#   cp /usr/share/maildancer/system.sieve /opt/infodancer/domains/system.sieve
#
# It has to live in the data tree rather than the config tree, and has to be
# world-readable: the script is read by mail-session, which by then has dropped
# to the recipient's uid and cannot reach the config tree at all. Nothing in
# here is secret.
#
# Deleting the file disables site-wide filing; delivery is unaffected. So is a
# syntax error, which falls through to implicit keep (RFC 5228 2.10.6) -- but it
# fails silently for every user at once, so check changes before installing:
#
#   sieve-test system.sieve message.eml     # or deliver a message to a test account

require ["fileinto", "environment"];

# File what the scanner itself called spam.
#
# This keys on the verdict carried out of band on the delivery channel, NOT on
# the message's X-Spam-* headers. Those are advisory and arrive on data the
# sender chose, so a sender could set X-Spam-Flag: NO and skip the filter -- or
# set YES on a clean message and file a victim's real mail into their Junk.
# The environment item cannot be forged: it never appears in the message.
#
# Deliberately no threshold of our own on top of the scanner's. rspamd already
# refuses what it is confident about at SMTP time; this covers the band below
# that, and picking a second number here would just be a worse copy of a
# decision rspamd makes with far more context.
#
# Unscanned mail is untouched: with no scan the item is unsupported, and
# RFC 5183 section 4 makes a test against an unsupported item fail
# unconditionally. "Not scanned" is not "spam", and it is not "clean" either.
if environment :is "vnd.maildancer.spam-flag" "YES" {
    fileinto "Junk";
}

# To be stricter than the scanner, compare the normalized score instead. It runs
# 0..10 (RFC 5235): 0 not tested, 1 clean, 10 certain spam. Lower the number to
# file more aggressively.
#
#   require ["fileinto", "environment", "relational", "comparator-i;ascii-numeric"];
#   if environment :value "ge" :comparator "i;ascii-numeric" "vnd.maildancer.spam-value" "5" {
#       fileinto "Junk";
#   }
#
# Compare spam-value, never spam-score: Sieve's only numeric comparator
# (i;ascii-numeric, RFC 4790) is defined over non-negative integers, so it reads
# a decimal score as its integer part and gives a negative one no ordering at
# all. Such a rule looks correct and behaves arbitrarily.

# Anything not filed above falls through to implicit keep -- the inbox.
