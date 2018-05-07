#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "config.h"
#include "memory.h"
#include "cmark.h"
#include "node.h"
#include "cmark_extension_api.h"
#include "syntax_extension.h"
#include "parser.h"
#include "registry.h"

#include "../extensions/core-extensions.h"

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <io.h>
#include <fcntl.h>
#endif

static const char *gfm_extensions[] = { "table", "strikethrough", "autolink", "tagfilter" };
static const int gfm_mounted_all = 4;
static const int gfm_mounted_no_tag_filter = 3;

typedef enum {
  FORMAT_NONE,
  FORMAT_HTML,
  FORMAT_XML,
  FORMAT_MAN,
  FORMAT_COMMONMARK,
  FORMAT_PLAINTEXT,
  FORMAT_LATEX
} writer_format;

void print_usage() {
  printf("Usage:   cmark-gfm [FILE*]\n");
  printf("Options:\n");
  printf("  --to, -t FORMAT  Specify output format (html, xml, man, "
         "commonmark, plaintext, latex)\n");
  printf("  --width WIDTH    Specify wrap width (default 0 = nowrap)\n");
  printf("  --sourcepos      Include source position attribute\n");
  printf("  --hardbreaks     Treat newlines as hard line breaks\n");
  printf("  --nobreaks       Render soft line breaks as spaces\n");
  printf("  --safe           Suppress raw HTML and dangerous URLs\n");
  printf("  --smart          Use smart punctuation\n");
  printf("  --validate-utf8  Replace UTF-8 invalid sequences with U+FFFD\n");
  printf("  --github-pre-lang Use GitHub-style <pre lang> for code blocks\n");
  printf("  --footnotes      Parse footnotes\n");
  printf("  --extension, -e EXTENSION_NAME Specify an extension name to use\n");
  printf("  --list-extensions              List available extensions and quit\n");
  printf("  --strikethrough-double-tilde   Only parse strikethrough (if enabled)\n");
  printf("                                 with two tildes\n");
  printf("  --table-prefer-style-attributes Use style attributes to align table cells\n"
         "                                  instead of align attributes.\n");
  printf("  --help, -h       Print usage information\n");
  printf("  --version        Print version\n");
}

static bool print_document(cmark_node *document, writer_format writer,
                           int options, int width, cmark_parser *parser) {
  char *result;

  cmark_mem *mem = cmark_get_default_mem_allocator();

  switch (writer) {
  case FORMAT_HTML:
    result = cmark_render_html_with_mem(document, options, parser->syntax_extensions, mem);
    break;
  case FORMAT_XML:
    result = cmark_render_xml_with_mem(document, options, mem);
    break;
  case FORMAT_MAN:
    result = cmark_render_man_with_mem(document, options, width, mem);
    break;
  case FORMAT_COMMONMARK:
    result = cmark_render_commonmark_with_mem(document, options, width, mem);
    break;
  case FORMAT_PLAINTEXT:
    result = cmark_render_plaintext_with_mem(document, options, width, mem);
    break;
  case FORMAT_LATEX:
    result = cmark_render_latex_with_mem(document, options, width, mem);
    break;
  default:
    fprintf(stderr, "Unknown format %d\n", writer);
    return false;
  }
  printf("%s", result);
  mem->free(result);

  return true;
}

static void print_extensions(void) {
  cmark_llist *syntax_extensions;
  cmark_llist *tmp;

  printf ("Available extensions:\n");

  cmark_mem *mem = cmark_get_default_mem_allocator();
  syntax_extensions = cmark_list_syntax_extensions(mem);
  for (tmp = syntax_extensions; tmp; tmp=tmp->next) {
    cmark_syntax_extension *ext = (cmark_syntax_extension *) tmp->data;
    printf("%s\n", ext->name);
  }

  cmark_llist_free(mem, syntax_extensions);
}

int main(int argc, char *argv[]) {
  int i, numfps = 0;
  int *files;
  char buffer[4096];
  cmark_parser *parser = NULL;
  size_t bytes;
  cmark_node *document = NULL;
  int width = 0;
  char *unparsed;
  writer_format writer = FORMAT_HTML;
  int options = CMARK_OPT_DEFAULT;
  int res = 1;

  core_extensions_ensure_registered();

#if defined(_WIN32) && !defined(__CYGWIN__)
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
#endif

  files = (int *)calloc(argc, sizeof(*files));

  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--version") == 0) {
      printf("cmark %s", CMARK_VERSION_STRING);
      printf(" - CommonMark converter\n(C) 2014-2016 John MacFarlane\n");
      goto success;
    } else if (strcmp(argv[i], "--list-extensions") == 0) {
      print_extensions();
      goto success;
    } else if (strcmp(argv[i], "--table-prefer-style-attributes") == 0) {
      options |= CMARK_OPT_TABLE_PREFER_STYLE_ATTRIBUTES;
    } else if (strcmp(argv[i], "--strikethrough-double-tilde") == 0) {
      options |= CMARK_OPT_STRIKETHROUGH_DOUBLE_TILDE;
    } else if (strcmp(argv[i], "--sourcepos") == 0) {
      options |= CMARK_OPT_SOURCEPOS;
    } else if (strcmp(argv[i], "--hardbreaks") == 0) {
      options |= CMARK_OPT_HARDBREAKS;
    } else if (strcmp(argv[i], "--nobreaks") == 0) {
      options |= CMARK_OPT_NOBREAKS;
    } else if (strcmp(argv[i], "--smart") == 0) {
      options |= CMARK_OPT_SMART;
    } else if (strcmp(argv[i], "--github-pre-lang") == 0) {
      options |= CMARK_OPT_GITHUB_PRE_LANG;
    } else if (strcmp(argv[i], "--footnotes") == 0) {
      options |= CMARK_OPT_FOOTNOTES;
    } else if (strcmp(argv[i], "--safe") == 0) {
      options |= CMARK_OPT_SAFE;
    } else if (strcmp(argv[i], "--validate-utf8") == 0) {
      options |= CMARK_OPT_VALIDATE_UTF8;
    } else if (strcmp(argv[i], "--liberal-html-tag") == 0) {
      options |= CMARK_OPT_LIBERAL_HTML_TAG;
    } else if ((strcmp(argv[i], "--help") == 0) ||
               (strcmp(argv[i], "-h") == 0)) {
      print_usage();
      goto success;
    } else if (strcmp(argv[i], "--width") == 0) {
      i += 1;
      if (i < argc) {
        width = (int)strtol(argv[i], &unparsed, 10);
        if (unparsed && strlen(unparsed) > 0) {
          fprintf(stderr, "failed parsing width '%s' at '%s'\n", argv[i],
                  unparsed);
          goto failure;
        }
      } else {
        fprintf(stderr, "--width requires an argument\n");
        goto failure;
      }
    } else if ((strcmp(argv[i], "-t") == 0) || (strcmp(argv[i], "--to") == 0)) {
      i += 1;
      if (i < argc) {
        if (strcmp(argv[i], "man") == 0) {
          writer = FORMAT_MAN;
        } else if (strcmp(argv[i], "html") == 0) {
          writer = FORMAT_HTML;
        } else if (strcmp(argv[i], "xml") == 0) {
          writer = FORMAT_XML;
        } else if (strcmp(argv[i], "commonmark") == 0) {
          writer = FORMAT_COMMONMARK;
        } else if (strcmp(argv[i], "plaintext") == 0) {
          writer = FORMAT_PLAINTEXT;
        } else if (strcmp(argv[i], "latex") == 0) {
          writer = FORMAT_LATEX;
        } else {
          fprintf(stderr, "Unknown format %s\n", argv[i]);
          goto failure;
        }
      } else {
        fprintf(stderr, "No argument provided for %s\n", argv[i - 1]);
        goto failure;
      }
    } else if ((strcmp(argv[i], "-e") == 0) || (strcmp(argv[i], "--extension") == 0)) {
      i += 1; // Simpler to handle extensions in a second pass, as we can directly register
              // them with the parser.
    } else if (*argv[i] == '-') {
      print_usage();
      goto failure;
    } else { // treat as file argument
      files[numfps++] = i;
    }
  }

#if DEBUG
  parser = cmark_parser_new(options);
#else
  parser = cmark_parser_new_with_mem(options, cmark_get_arena_mem_allocator());
#endif

  for (i = 1; i < argc; i++) {
    if ((strcmp(argv[i], "-e") == 0) || (strcmp(argv[i], "--extension") == 0)) {
      i += 1;
      if (i < argc) {
        cmark_syntax_extension *syntax_extension = cmark_find_syntax_extension(argv[i]);
        if (!syntax_extension) {
          fprintf(stderr, "Unknown extension %s\n", argv[i]);
          goto failure;
        }
        cmark_parser_attach_syntax_extension(parser, syntax_extension);
      } else {
        fprintf(stderr, "No argument provided for %s\n", argv[i - 1]);
        goto failure;
      }
    }
  }

  for (i = 0; i < numfps; i++) {
    FILE *fp = fopen(argv[files[i]], "rb");
    if (fp == NULL) {
      fprintf(stderr, "Error opening file %s: %s\n", argv[files[i]],
              strerror(errno));
      goto failure;
    }

    while ((bytes = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
      cmark_parser_feed(parser, buffer, bytes);
      if (bytes < sizeof(buffer)) {
        break;
      }
    }

    fclose(fp);
  }

  if (numfps == 0) {
    while ((bytes = fread(buffer, 1, sizeof(buffer), stdin)) > 0) {
      cmark_parser_feed(parser, buffer, bytes);
      if (bytes < sizeof(buffer)) {
        break;
      }
    }
  }

  document = cmark_parser_finish(parser);

  if (!document || !print_document(document, writer, options, width, parser))
    goto failure;

success:
  res = 0;

failure:

#if DEBUG
  if (parser)
  cmark_parser_free(parser);

  if (document)
    cmark_node_free(document);
#else
  cmark_arena_reset();
#endif

  cmark_release_plugins();

  free(files);

  return res;
}

char *cmark_gfm_markdown_to_html(const char *text, size_t len, int options, int no_tag_filter) {
  core_extensions_ensure_registered();

  cmark_mem *mem = cmark_get_default_mem_allocator();
  cmark_parser *parser = cmark_parser_new_with_mem(options, mem);

  int mounted = no_tag_filter ? gfm_mounted_no_tag_filter : gfm_mounted_all;
  for (int i = 0; i < mounted; i++) {
      cmark_syntax_extension *extension = cmark_find_syntax_extension(gfm_extensions[i]);
      if (extension) {
          cmark_parser_attach_syntax_extension(parser, extension);
      }
  }

  cmark_parser_feed(parser, text, len);
  cmark_node *document = cmark_parser_finish(parser);

  char *result = cmark_render_html_with_mem(document, options, cmark_parser_get_syntax_extensions(parser), mem);

  cmark_parser_free(parser);
  cmark_node_free(document);
  return result;
}
