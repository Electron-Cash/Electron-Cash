#!/usr/bin/env python3
#
# Generates strings.xml files from the gettext files. This script is run automatically by the
# Gradle task `generateStrings`.
#
# This script's requirements are listed in build-requirements.txt. It also runs
# contrib/make_locale, which requires the external commands `xgettext` and `msgfmt`.

# Strings to test when changing this script:
#
# * String with no fields, e.g. "New wallet"
# * % syntax:
#   * Single implicit field, e.g. "%s bytes"
#   * Single indexed field (no examples in catalog)
#   * Multiple implicit fields (no examples in catalog)
#   * Multiple indexed fields, e.g. "%1$d tx (%2$d unverified)"
#   * Plurals, e.g. "Sweep %d input(s)"
# * {} syntax:
#   * Single implicit field, e.g. "{} copied to clipboard"
#   * Single keyword field, e.g. "Size: {size} bytes" (no examples on Android, except for
#     the plural below)
#   * Multiple implicit fields, e.g. "{} contacts exported to '{}'" (no examples on Android)
#   * Multiple keyword fields, e.g. "Please wait... {num}/{total}" (no examples on Android)
#   * Plurals, e.g. "{conf} confirmation(s)"


import argparse
import babel
from collections import Counter, defaultdict
from datetime import datetime
import os
from os.path import abspath, basename, dirname, isdir, join
import polib
import re
from subprocess import run
import sys


SCRIPT_NAME = basename(__file__)
EC_ROOT = abspath(join(dirname(__file__), "../.."))


JAVA_KEYWORDS = set([
    "_", "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
    "const", "continue", "default", "do", "double ", "else", "enum", "extends", "false", "final",
    "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
    "interface ", "long", "native", "new", "null", "package", "private", "protected", "public",
    "return", "short", "static", "strictfp", "super", "switch ", "synchronized", "this",
    "throw", "throws", "transient", "true", "try", "void", "volatile", "while"])

KOTLIN_KEYWORDS = set([  # "Hard" keywords only.
    "as", "break", "class", "continue", "do", "else", "false", "for", "fun", "if", "in",
    "interface", "is", "null", "object", "package", "return", "super", "this", "throw",
    "true", "try", "typealias", "typeof" "val", "var", "when", "while"])

KEYWORDS = JAVA_KEYWORDS | KOTLIN_KEYWORDS

# Some language codes have been renamed, but Android only recognizes the old codes in resource
# directory names.
RENAMED_LANGUAGES = {
    "he": "iw",
    "yi": "ji",
    "id": "in",
}


catalog_errors = 0

class CatalogError(Exception):
    def __init__(self, message):
        super().__init__(message)
        global catalog_errors
        catalog_errors += 1


def main():
    global args
    args = parse_args()
    if not args.no_download:
        log("Running make_locale")
        run([sys.executable, join(EC_ROOT, "contrib/make_locale")], check=True)

    locale_dir = join(EC_ROOT, "electroncash/locale")
    src_strings = read_catalog(join(locale_dir, "messages.pot"), "en", "US")

    lang_strings = defaultdict(list)
    for lang_region in [name for name in os.listdir(locale_dir)
                        if isdir(join(locale_dir, name)) and name != '__pycache__']:
        lang, region = lang_region.split("_")
        catalog = read_catalog(join(locale_dir, lang_region, "LC_MESSAGES", "electron-cash.po"),
                               lang, region)
        lang_strings[lang].append((region, catalog))

    if catalog_errors:
        sys.exit(1)

    log(f"Writing to {args.out}")
    ids = make_ids(src_strings)
    write_xml(args.out, "", src_strings, ids)
    for lang, region_strings in lang_strings.items():
        region_strings.sort(key=region_order, reverse=True)
        for i, (region, strings) in enumerate(region_strings):
            write_xml(args.out, lang if i == 0 else "{}-r{}".format(lang, region),
                      strings, ids)


def read_catalog(filename, lang, region):
    lang_region = f"{lang}_{region}"

    try:
        is_pot = filename.endswith(".pot")
        f = polib.pofile(filename)
        pf = f.metadata.get("Plural-Forms")
        if pf is None:
            quantities = None
        elif is_pot:
            quantities = ["one", "other"]
        else:
            match = re.search(r"nplurals=(\d+);", pf)
            if not match:
                raise CatalogError("Failed to parse Plural-Forms")
            nplurals = int(match.group(1))

            try:
                locale = babel.Locale(lang_region)
            except babel.UnknownLocaleError:
                locale = babel.Locale(lang)

            quantities = sorted(locale.plural_form.tags | {"other"},
                                key=["zero", "one", "two", "few", "many", "other"].index)
            if len(quantities) != nplurals:
                raise CatalogError(f"Plural-Forms says {nplurals=}, but Babel has "
                                   f"{len(quantities)} plural tags for this language {quantities}")
    except CatalogError as e:
        log(f"{filename}: {e}", file=sys.stderr)
        return None

    catalog = {}
    for entry in f:
        try:
            msgid = entry.msgid
            if is_excluded(msgid):
                continue

            if entry.msgid_plural:
                # Get field indices from msgid_plural, because sometimes msgid just contains a
                # singular word with no field.
                indices = get_indices(entry.msgid_plural)

                # Only include the string if it has a complete set of plural translations,
                # otherwise some numbers would cause it to appear blank.
                msgstr_plural = ({0: msgid, 1: entry.msgid_plural} if is_pot
                                 else entry.msgstr_plural)
                if not all(s for s in msgstr_plural.values()):
                    continue

                if quantities is None:
                    raise CatalogError("msgid {msgid!r} has plurals, but file has no Plural-Forms")
                catalog[msgid] = {quantities[i]: fix_format(s, indices)
                                  for i, s in msgstr_plural.items()}
            else:
                indices = get_indices(msgid)
                msgstr = msgid if is_pot else entry.msgstr
                if not msgstr:
                    continue
                catalog[msgid] = fix_format(msgstr, indices)
        except CatalogError as e:
            log(f"{filename}:{entry.linenum}: {e}", file=sys.stderr)

    return catalog


# Takes a source string in {} or % format, and returns a dict mapping its field keywords and
# indices (explicit or implicit) to % field indices to use in the output.
def get_indices(s):
    indices = {}

    # {} field indices are assigned in the order each field first appears in the string.
    matches = get_brace_fields(s)
    if matches:
        for _, index in matches:
            if index not in indices:
                indices[index] = len(indices) + 1

    # % field indices are taken directly from the string, so they may leave gaps.
    else:
        matches = get_percent_fields(s)
        for _, index in matches:
            indices[index] = int(index)

    return indices


# Takes a string in {} or % format, and converts it to Java-compatible % format, taking into
# account the given field indices generated by get_indices. Strings which are already in %
# format will be checked for errors and returned unchanged.
#
# A string having fewer fields than the msgid isn't necessarily an error, e.g. some
# translations omit a numeric field and use the equivalent of "a" or "one" instead. But if a
# string references a field that isn't in the msgid, that usually causes a crash (e.g. #2358).
def fix_format(s, indices):
    INDEX_ERROR = "string {!r} uses field {!r}, which isn't in the msgid"

    matches = get_brace_fields(s)
    if matches:
        # The string uses {} format, so any % signs cannot be fields, and should be escaped.
        result = s.replace("%", "%%")

        for field, index in matches:
            try:
                index_out = indices[index]
            except KeyError:
                if index not in args.ignore_unknown_keywords:
                    raise CatalogError(INDEX_ERROR.format(s, index))
            else:
                result = result.replace(field,
                                        "%s" if (len(indices) == 1) else f"%{index_out}$s",
                                        1)
        return result

    else:
        matches = get_percent_fields(s)
        for field, index in matches:
            # Only numeric fields allow a space flag. A space in any other field type is
            # probably a typo (e.g. #1899) or an unescaped % sign.
            if (" " in field) and (field[-1].lower() not in "doxefga"):
                raise CatalogError(f"in string {s!r}, non-numeric field {field!r} contains a space")

            if index not in indices:
                raise CatalogError(INDEX_ERROR.format(s, index))

        return s


# Return a list of {} fields in a string. Each field is returned as a tuple of:
#   * The entire field, including the braces.
#   * The field keyword or index as a string, with implicit fields numbered from 0.
def get_brace_fields(s):
    # TODO: handle more complex syntax like "{x:.3f}".
    matches = re.findall(r"(\{(\w+)?\})", s)
    return fill_implicit(matches, 0)


# Return a list of % fields in a string. Each field is returned as a tuple of:
#   * The entire field, including the %.
#   * The field index as a string, with implicit fields numbered from 1.
def get_percent_fields(s):
    matches = re.findall(r"(%(?:(\d+)\$)?.*?[a-zA-Z])", s.replace("%%", ""))
    return fill_implicit(matches, 1)


def fill_implicit(matches, start):
    next = start

    result = []
    for i, (field, index) in enumerate(matches):
        if not index:
            index = str(next)
            next += 1
        result.append((field, index))
    return result


# The region with the most translations is output without a country code so it will act as
# a fallback for the others.
#
# Apparently Android 7 and later treats traditional and simplified Chinese as unrelated
# languages. Since it interprets "zh" as being simplified, it will never use it in any
# traditional locale, preferring English instead
# (https://gist.github.com/amake/0ac7724681ac1c178c6f95a5b09f03ce). We work around this by
# giving priority to zh_CN (simplified Chinese), so it is always output as values-zh,
# irrespective of how many translations it contains.
def region_order(item):
    region, strings = item
    return (region == "CN",   # "zh" must always be simplified Chinese: see comment above.
            len(strings))


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-download", action="store_true", help="Don't run make_locale")
    ap.add_argument("--ignore-unknown-keywords", metavar="KEYWORD", nargs="+", default=[],
                    help="Keywords which can appear in a string without being in the msgid")
    ap.add_argument("--out", metavar="DIR", type=abspath, required=True,
                    help="Output resources directory")
    return ap.parse_args()


def is_excluded(src_str):
    return bool(re.search(r"^\W*$", src_str))  # Empty or only punctuation.


# Returns a dict {s: id} where each `s` is a string in `strings`, and `id` is a unique
# Java/Kotlin identifier generated from it.
def make_ids(strings):
    ids_out = {}
    for id_options in [dict(lower=True, squash=True),
                       dict(lower=True, squash=False),
                       dict(lower=False, squash=False)]:
        ids_in = {s: tuple(str_to_id(s, **id_options).split("_"))
                  for s in strings}
        try:
            make_ids_inner(ids_in, ids_out)
            return {s: "_".join(id) for s, id in ids_out.items()}
        except DuplicateStringError:
            strings = list(ids_in)

    # The remaining strings differ only in equal-length sequences of space or punctuation. We
    # could handle this by generating unique suffixes for the ID, but that could cause the ID
    # to get a different value when the string set changes. So it's safer to just list the
    # undesired string in is_excluded.
    raise Exception("Failed to make unique IDs for the following strings:\n" +
                    "\n".join(repr(s) for s in sorted(strings, key=case_insensitive)))


def make_ids_inner(ids_in, ids_out):
    max_words = 2
    existing_ids = list(ids_out.values())
    prev_counts = None
    while ids_in:
        counts = Counter(existing_ids)
        counts.update([shorten_id(id, max_words) for id in ids_in.values()])
        if counts == prev_counts:
            raise DuplicateStringError()

        strings_done = []
        for s, id in ids_in.items():
            short_id = shorten_id(id, max_words)
            if counts[short_id] == 1:
                ids_out[s] = short_id
                strings_done.append(s)
        for s in strings_done:
            del ids_in[s]

        prev_counts = counts
        max_words += 1


# We still need to preserve empty words to avoid duplicate IDs. But we don't count them against
# the word limit, otherwise we end up with IDs like "__1" or "_", the last of which isn't even
# legal in Java 9.
def shorten_id(id, max_words):
    result = []
    num_words = 0
    for word in id:
        result.append(word)
        if word:
            num_words += 1
        if num_words == max_words:
            break
    return tuple(result)


class DuplicateStringError(Exception):
    pass


# Returns an identifier generated from every word in the given string.
def str_to_id(s, *, lower, squash):
    s_original = s
    s = s.replace("'", "")  # Combine contractions.
    if lower:
        s = s.lower()

    if squash:
        s = re.sub(r"%\S+", "", s)  # Remove placeholders.
        pattern = r"\W+"
        lstrip = "0123456789_"
        rstrip = "_"
    else:
        pattern = r"\W"
        lstrip = "0123456789"
        rstrip = ""
    id = (re.sub(pattern, "_", s, flags=re.ASCII)  # Remove invalid characters.
          .lstrip(lstrip)
          .rstrip(rstrip))

    if not id or not re.search(r"^[a-zA-Z_]", id):
        if squash:
            return str_to_id(s_original, lower=lower, squash=False)
        else:
            raise Exception(f"string {s_original!r} generated invalid identifier {id!r}")

    if id in KEYWORDS:
        id += "_"
    return id


def write_xml(res_dir, res_suffix, strings, ids):
    res_suffix = RENAMED_LANGUAGES.get(res_suffix, res_suffix)
    dir_name = "values" + ("-" + res_suffix if res_suffix else "")
    base_name = "strings.xml"
    log("{}/{}: ".format(dir_name, base_name), end="")
    abs_dir_name = join(res_dir, dir_name)
    os.makedirs(abs_dir_name, exist_ok=True)

    timestamp = datetime.utcnow().isoformat()
    output = sorted(((ids[src_str], tgt)
                     for src_str, tgt in strings.items()
                     if src_str in ids),  # Crowdin strings may not be in our local source.
                    key=lambda x: case_insensitive(x[0]))
    with open(join(abs_dir_name, base_name), "w", encoding="UTF-8") as f:
        print('<?xml version="1.0" encoding="utf-8"?>', file=f)
        print('<!-- Generated by {} at {} -->'.format(SCRIPT_NAME, timestamp), file=f)
        print('<!-- DO NOT EDIT this file directly. See "Strings" in android/README.md. -->',
              file=f)
        print('<resources>', file=f)
        for id, tgt in output:
            if isinstance(tgt, dict):
                print('    <plurals name="{}">'.format(id), file=f)
                for quantity, s in tgt.items():
                    print('        <item quantity="{}">{}</item>'
                          .format(quantity, str_for_xml(s)), file=f)
                print('    </plurals>', file=f)
            else:
                print('    <string name="{}">{}</string>'.format(id, str_for_xml(tgt)), file=f)
        print('</resources>', file=f)

    log("{} items".format(len(output)))


XML_REPLACEMENTS = [
    # Generic XML syntax
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),

    # Android-specific syntax
    # (https://developer.android.com/guide/topics/resources/string-resource#escaping_quotes)
    (re.compile(r"^([@?])"), r"\\\1"),
    ("'", r"\'"),
    ('"', r'\"'),
    ("\n", r"\n"),
]

def str_for_xml(s):
    for old, new in XML_REPLACEMENTS:
        if isinstance(old, str):
            s = s.replace(old, new)
        else:
            s = re.sub(old, new, s)
    return s


def log(*args, **kwargs):
    print(*args, **kwargs)
    kwargs.get("file", sys.stdout).flush()


def case_insensitive(s):
    return (s.lower(), s)


if __name__ == "__main__":
    main()
