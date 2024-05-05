/* BSD 2-Clause License - by rilysh */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sys/types.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <zip.h>

#ifdef NO_COLOR
# define HASHSIGN_COLOR           ""
# define STAR_COLOR               ""
# define UNDERLINE                ""
# define ITALIC                   ""
# define END_COLOR                ""

# define HEADER_START_COLOR       ""
# define HEADER_END_COLOR         ""
# define DESC_COLOR               ""
# define INBCKTCK_COLOR           ""
# define INSIDE_START_COLOR       ""
# define BODYHEAD_COLOR           ""
# define BODYCON_START_COLOR      ""
# define BODYCON_END_COLOR        ""
# define BRACES_START_COLOR       ""
# define BRACES_END_COLOR         ""

/* These values shall be put in a config header file. */
# define DOT_DOT_START_COLOR      ""
# define DOT_DOT_END_COLOR        ""
# define OK_START_COLOR           ""
# define OK_END_COLOR             ""
#else /* else */
# define HASHSIGN_COLOR           "\x1b[0;91m"
# define STAR_COLOR               "\x1b[1;92m"
# define UNDERLINE                "\x1b[4m"
# define ITALIC                   "\x1b[3m"
# define END_COLOR                "\x1b[0m"

# define HEADER_START_COLOR       "\x1b[1;95m"
# define HEADER_END_COLOR         "\x1b[0m"
# define DESC_COLOR               "\x1b[0;37m"
# define INBCKTCK_COLOR           "\x1b[1;97m"
# define INSIDE_START_COLOR       "\x1b[1;91m"
# define BODYHEAD_COLOR           "\x1b[0;97m"
# define BODYCON_START_COLOR      "\x1b[1;97m"
# define BODYCON_END_COLOR        "\x1b[0m"
# define BRACES_START_COLOR       "\x1b[0;91m"
# define BRACES_END_COLOR         "\x1b[0m"

/* These values shall be put in a config header file. */
# define DOT_DOT_START_COLOR      "\x1b[0;91m"
# define DOT_DOT_END_COLOR        "\x1b[0m"
# define OK_START_COLOR           "\x1b[1;92m"
# define OK_END_COLOR             "\x1b[0m"
#endif

/* Maximum decompressed buffer size that will be read and
   then written to the disk. */
#define ZBUF_MAX                 (1024)

/* Default will be always english. This path is works as
   a placeholder, if a specific language is provided or
   set in the system settings, it will add the extension
   at the end of the string. (e.g. lang=ja, output=.mmdr/pages.ja */
#define ARCHIVE_PATH        ".mmdr/pages"
#define DEFAULT_LANGCODE    "en"
#define ARCHIVE_ZIP_URL     "https://tinyurl.com/fbhhjj7j"

/* Noreturn specifier. */
#if defined (__GNUC__) || defined (__clang__) || defined (__TINYC__)
# define dead_end           __attribute__((noreturn))
#else
# define dead_end
#endif

static __inline__ const char *get_system_type_comptime(void)
{
	/* GNU/Linux */
#if defined (__linux__)
        return ("linux");

	/* FreeBSD */
#elif defined (__FreeBSD__)
        return ("freebsd");

	/* NetBSD */
#elif defined (__NetBSD__)
	return ("netbsd");

	/* OpenBSD */
#elif defined (__OpenBSD__)
	return ("openbsd");

	/* Android */
#elif defined (__ANDROID__)
	return ("android");

	/* Apple macOS (previously known as OS X) */
#elif defined (__APPLE__)
	return ("osx");

	/* Don't fallback. Platform that TL;DR pages don't
	   support yet is an error here. */
#else
# error unknown system
#endif
}

static char *do_format_file(const char *sys, const char *lang, const char *com)
{
	char *user, *p;
	size_t asz, bsz;
	struct passwd *pwd;
	uid_t uid;

	if (sys == NULL)
		sys = get_system_type_comptime();

	/* Try with getenv() first, this avoids additional allocation
	   for the database. */
	user = getenv("USER");
	if (user == NULL) {		
		uid = getegid();
		pwd = getpwuid(uid);
		if (pwd == NULL)
			err(EXIT_FAILURE, "getpwuid()");

		/* Set the username. */
		user = pwd->pw_name;
	}

	asz = strlen(user) + strlen(com) + strlen(sys) + strlen(lang);
	/* /home/ = 6, /.// = 4, extra = 1 */
	bsz = sizeof(ARCHIVE_PATH) + 6 + 4 + 1;
	p = calloc(asz + bsz + 1, sizeof(char));
	if (p == NULL)
		err(EXIT_FAILURE, "calloc()");

	snprintf(p, asz + bsz, "/home/%s/%s.%s/%s/%s",
		 user, ARCHIVE_PATH, lang, sys, com);
	return (p);
}

static char *do_format_path(const char *lang)
{
	char *user, *p;
	size_t asz, bsz;
	struct passwd *pwd;
	uid_t uid;

	/* Same description as the earlier one. */
	user = getenv("USER");
	if (user == NULL) {
		uid = getegid();
		pwd = getpwuid(uid);
		if (pwd == NULL)
			err(EXIT_FAILURE, "getpwuid()");

		/* Set the username. */
		user = pwd->pw_name;
	}

	asz = strlen(user) + strlen(lang);
	/* /home/ = 6, /./ = 3, extra = 1 */
	bsz = sizeof(ARCHIVE_PATH) + 6 + 3 + 1;
	p = calloc(asz + bsz + 1, sizeof(char));
	if (p == NULL)
		err(EXIT_FAILURE, "calloc()");

	snprintf(p, asz + bsz, "/home/%s/%s.%s/",
		 user, ARCHIVE_PATH, lang);
	return (p);
}

static char *do_format_zip_path(const char *path)
{
	const char *user;
	char *p;
	struct passwd *pwd;
	size_t alen, blen;
	gid_t uid;

	user = getenv("USER");
	if (user == NULL) {
		uid = getegid();
		pwd = getpwuid(uid);
		if (pwd == NULL)
			errx(EXIT_FAILURE,
			     "error: no system username was found.");
	}

	if (path == NULL) {
		alen = strlen(user);
		blen = alen + 6 + 6 + 1;
		p = calloc(blen, sizeof(char));
		if (p == NULL)
			err(EXIT_FAILURE, "calloc()");

		snprintf(p, blen, "/home/%s/.mmdr", user);
	} else {
		alen = strlen(user) + strlen(path);
		/* <username> + /home/ + /.mmdr/ + (nul terminator) */
		blen = alen + 6 + 7 + 1;
		p = calloc(blen, sizeof(char));
		if (p == NULL)
			err(EXIT_FAILURE, "calloc()");

		snprintf(p, blen, "/home/%s/.mmdr/%s", user, path);
	}
        return (p);
}

static char *look_for_tldr(const char *sys, const char *arg_lang, const char *com)
{
	char *lang, *langs, *sep;
	char *p;
	size_t asz, bsz;
	char *tok, *stok;

	if (arg_lang) {
	        p = do_format_file(sys, arg_lang, com);
		if (access(p, F_OK) == -1) {
			free(p);
			p = do_format_file("common", arg_lang, com);
			if (access(p, F_OK) == -1)
			        return (NULL);
		        else
				return (p);
		}

		return (p);
		/* Unreachable. */
	}

	lang = getenv("LANG");
	if (lang == NULL)
		/* Fallback to default settings. */
		lang = DEFAULT_LANGCODE;

	langs = getenv("LANGUAGE");
	if (langs == NULL)
		langs = "";

	asz = strlen(lang);
	bsz = strlen(langs);

	/* LANG  LANGUAGE  Result
	   unset it:cz     en
	   unset unset     en */
	if ((asz == 0 && bsz == 0) ||
	    (asz == 0 && bsz > 0)) {
		p = do_format_file(sys, "en", com);
	        if (access(p, F_OK) == -1) {
			free(p);
			/* Fallback to common directory. */	
			p = do_format_file("common", "en", com);
			if (access(p, F_OK) == -1)
				return (NULL);
			else
				return (p);
		} else {
			return (p);
		}
	}

	/* LANG  LANGUAGE  Result
	   it    unset     it, en */
	else if (asz > 0 && bsz == 0) {
		/* Try without spliting the "lang" variable. */
		p = do_format_file(sys, lang, com);
		if (access(p, F_OK) == -1)
			free(p);
		else
			return (p);

		/* If that fails, split the variable and try again. */
		sep = strsep(&lang, "_");
		if (sep == NULL)
			sep = lang;

		p = do_format_file(sys, sep, com);
		if (access(p, F_OK) == -1) {
			free(p);
			/* Fallback to English. */
			p = do_format_file(sys, "en", com);
			if (access(p, F_OK) == -1) {
				free(p);
				/* Fallback to common directory. */
				p = do_format_file("common", "en", com);
				if (access(p, F_OK) == -1)
					return (NULL);
				else
					return (p);
			} else {
				return (p);
			}
		} else {
			return (p);
		}
	}

	/* LANG  LANGUAGE  Result
	   cz    it:cz:de  it, cz, de, en
	   cz    it:de:fr  it, de, fr, cz, en */
	else if (asz > 0 && bsz > 0) {
		while ((stok = strsep(&langs, ":"))) {
			/* Try without spliting the "lang" variable. */
			p = do_format_file(sys, stok, com);
			if (access(p, F_OK) == -1)
				free(p);
			else
				return (p);

			/* If that fails, split the variable and try again. */
			tok = strsep(&stok, "_");
			if (tok == NULL)
				tok = stok;
			p = do_format_file(sys, tok, com);
			/* Fallback to common directory. */
			if (access(p, F_OK) == -1) {
				free(p);
				p = do_format_file("common", tok, com);
				if (access(p, F_OK) == 0) {
				        return (p);
				} else {
					free(p);
				}
			} else {
				free(p);
			}
		}

		/* If we reached here, that means we wasn't able to
		   find our target file (command) in the language
		   directories. Default to English and see if the file
		   lives there (e.g. pages.en/{sys}/{file}). */
	        p = do_format_file(sys, "en", com);
		if (access(p, F_OK) == 0)
		        return (p);
		free(p);

		/* If we reached here, that means the previous
		   attempt was failed, and we wasn't able to
		   locate the file. This time, let's see if being
		   more specific can help us. (e.g.
		   pages.en/common/{file}). */
		p = do_format_file("common", "en", com);
		if (access(p, F_OK) == 0) {
			return (p);
		} else {
			free(p);
			/* We wasn't able to find a file matching
			   with the query. */
			return (NULL);
		}
	} else {
		/* Unreachable. */
	        return (NULL);
	}
}

static void unzip_zip_archive(const char *zpath, const char *dpath)
{
        zip_t *zip;
	zip_int64_t entries, reads;
	zip_uint64_t i;
	struct zip_stat zs;
	char zbuf[ZBUF_MAX];
        char *p, *r;
	size_t zlen, plen, mlen, tlen, bytes;
	zip_file_t *zfp;
	int fd;

	/* Check whether the source path (zip) file exists or not. */
	if (access(zpath, F_OK) == -1)
		errx(EXIT_FAILURE,
		     "error: zip file path does not exists.");

	/* Check whether the destination path exists or not. */
	if (access(dpath, F_OK) == -1)
		errx(EXIT_FAILURE,
		     "error: destination path does not exists.");

	p = calloc(1, sizeof(char));
	if (p == NULL)
		err(EXIT_FAILURE, "calloc()");

	zip = zip_open(zpath, 0, NULL);
	if (zip == NULL)
		err(EXIT_FAILURE, "zip_open()");
	entries = zip_get_num_entries(zip, 0);

	mlen = 0;
	for (i = 0; i < (zip_uint64_t)entries; i++) {
		if (zip_stat_index(zip, i, 0, &zs) == 0) {
		        zlen = strlen(zs.name);
			plen = strlen(dpath);
			if (mlen == 0) {
				/* Allocate memory to keep the formatted path stored. */
				tlen = (zlen + plen + 4) * 4;
				r = realloc(p, tlen);
				if (r == NULL) {
					/* Keeping open file descriptors are very costly.
					   Ensure cleanup before exiting. */
					zip_close(zip);
					free(p);
					err(EXIT_FAILURE, "realloc()");
				}

				p = r;
				mlen = tlen;
			} else {
				mlen -= zlen + plen + 4;
			}

			/* Destination place where the file will be created. */
			snprintf(p, zlen + plen + 3, "%s/%s", dpath, zs.name);

			/* If the file is a directory, create a directory for it. */
			if (zs.name[zlen - 1] == '/') {
			        if (mkdir(p, 0777) == -1) {
					if (errno != EEXIST) {
					        zip_close(zip);
						free(p);
						err(EXIT_FAILURE, "mkdir()");
					}
				}
			} else {
				/* For a file, create the file with proper permission bits,
				   and write the contents to that file descriptor. Also,
				   print the file name that's being inflated. */
			        fprintf(stdout,
				        " inflating: %s"
					DOT_DOT_START_COLOR" .. "DOT_DOT_END_COLOR, p);
				fflush(stdout);

			        zfp = zip_fopen_index(zip, i, 0);
			        fd = open(p, O_WRONLY | O_CREAT, 0644);
				if (fd == -1) {
					zip_fclose(zfp);
					zip_close(zip);
					free(p);
				        err(EXIT_FAILURE, "open()");
				}

			        bytes = 0;
				while (bytes != zs.size) {
					/* Read the file content and store it to zbuf. */
				        reads = zip_fread(zfp, zbuf, sizeof(zbuf));

					/* Write the contents that's in zbuf. */
					if (write(fd, zbuf, (size_t)reads) == -1) {
						zip_fclose(zfp);
						zip_close(zip);
						free(p);
						close(fd);
					        err(EXIT_FAILURE, "write()");
					}

					bytes += (size_t)reads;
				}

				close(fd);
				zip_fclose(zfp);

				/* Append a "ok" for parity. It doesn't say anything,
				   e.g. whether the file inflating was successful or
				   not. As if anything wrong  happens, it either will
				   get ignored or will be caught in error guards. */
			        fputs(OK_START_COLOR"[ok]\n"OK_END_COLOR, stdout);
			}
	        }
	}

	free(p);
	zip_close(zip);
}

static void parse_tldr_file(const char *fname)
{
	FILE *fp;
	char *l, *lptr;
	size_t nbytes;
	ssize_t lsz;
	int once;

	fp = fopen(fname, "r");
	if (fp == NULL)
		err(EXIT_FAILURE, "fopen()");

	lptr = NULL;
	nbytes = 0;
	once = 0;

	while ((lsz = getline(&lptr, &nbytes, fp)) != -1) {
		switch (*lptr) {
		case '#':
			l = lptr;
			l++;
			if (*l == ' ')
				l++;
			
		        fprintf(stdout,
				HASHSIGN_COLOR"# "HEADER_START_COLOR
				""UNDERLINE"%s"HEADER_END_COLOR"\n", l);
			break;

		case '>':
			l = lptr;
			l++;
			if (*l == ' ')
				l++;

			fputs(STAR_COLOR"* "DESC_COLOR, stdout);
		        for (; *l != '\n'; l++) {
				switch (*l) {
				case '`':
					/* Look for the next backtick. */
					l++;
					fputs(INBCKTCK_COLOR""ITALIC, stdout);
					/* No backtick? It's an error! */
					if (strchr(l, '`') == NULL)
						errx(EXIT_FAILURE,
						     "error: incomplete backtick.");
					for (; *l != '`'; l++)
						fputc(*l, stdout);
					fputs(DESC_COLOR, stdout);
				        break;

				case '<':
				        fputs(INSIDE_START_COLOR, stdout);
					if (strchr(l, '>') == NULL)
					        errx(EXIT_FAILURE,
						     "error: incomplete leading.");
					break;

				case '>':
					fputs(DESC_COLOR, stdout);
					break;

				default:
					fputc(*l, stdout);
					break;
				}
			}

			fputs(END_COLOR"\n", stdout);
			break;

		case '-':
			l = lptr;
			l++;
			if (*l == ' ')
				l++;
			if (once == 0) {
				fputc('\n', stdout);
				once = 1;
			}

		        fputs(STAR_COLOR"\u2022 "END_COLOR, stdout);
			for (; *l != '\n'; l++) {
				if (*l == '`') {
					/* Look for the next backtick. */
					l++;
					fputs(INBCKTCK_COLOR""ITALIC, stdout);

					/* No backtick? It's an error! */
					if (strchr(l, '`') == NULL)
						errx(EXIT_FAILURE,
						     "error: incomplete backtick.");
					for (; *l != '`'; l++)
						fputc(*l, stdout);
					fputs(BODYHEAD_COLOR, stdout);
			        } else {
					fputc(*l, stdout);
				}
			}
			fputc('\n', stdout);
		        break;

		case '`':
			l = lptr;
			l++;

			/* Check if the backtick ends or not. */
			if (strchr(l, '`') == NULL)
				errx(EXIT_FAILURE,
				     "error: incomplete backtick.");
			l[strcspn(l, "`")] = '\0';
			fputs(BODYCON_START_COLOR"~> ", stdout);

			for (; *l != '\n'; l++) {
				if (*l == '{' && *(l + 1) == '{') {
					/* leading "{{" */
					l++;
					fputs(BRACES_START_COLOR, stdout);
				} else if (*l == '}' && *(l + 1) == '}') {
					/* ending "}}" */
					l++;
					fputs(BODYCON_START_COLOR, stdout);
				} else {
					/* everything else. */
					fputc(*l, stdout);
				}
			}
			fputs("\n\n"BODYCON_END_COLOR, stdout);
			break;

		default:
		        break;
		}
        }

	free(lptr);
	fclose(fp);
}

static char *add_tldr_ext(const char *fname)
{
	char *p;
	size_t sz;

	/* Test to see if the file already has a ".md"
	   file extension. */
	if (strstr(fname, ".md")) {
		p = strdup(fname);
		if (p == NULL)
			return (NULL);
		return (p);
	}

	sz = strlen(fname);
	p = calloc(sz + (size_t)4, sizeof(char));
	if (p == NULL)
		return (NULL);

	memcpy(p, fname, sz);
	memcpy(p + sz, ".md", 3);

	return (p);
}

static void make_mmdr_directory(void)
{
	const char *user;
	struct passwd *pwd;
	size_t alen;
	char *p;

	user = getenv("USER");
	if (user == NULL) {
		pwd = getpwuid(getuid());
		if (pwd == NULL)
			errx(EXIT_FAILURE,
			     "no system username was found.");
		user = pwd->pw_name;
        }

	/* /home/<user>/.mmdr + 1 (nul-terminator) */
        alen = strlen(user) + 6 + 6 + 1;
	p = calloc(alen, sizeof(char));
	if (p == NULL)
		err(EXIT_FAILURE, "calloc()");

	snprintf(p, alen, "/home/%s/.mmdr/", user);
	if (access(p, F_OK) == -1) {
		switch (errno) {
		case ENOENT:
			if (mkdir(p, 766) == -1)
			        err(EXIT_FAILURE, "mkdir()");
			break;

		case EEXIST:
			errx(EXIT_FAILURE,
			     "path is already initialized.");

		default:
			err(EXIT_FAILURE, "access()");
		}
	}

	free(p);
}

dead_end
static void print_usage(int status)
{
	fprintf(stdout,
		"mmdr [-l -s -u -d]\n"
		" * -l\tspecify the page language\n"
		" * -s\tspecify the system name\n"
		" * -u\tunzip the 'tldr.zip' archive\n"
		" * -d\tdisplay info to retrieve the zip\n"
		" * -h\tthis menu\n");
	exit(status);
}

int main(int argc, char **argv)
{
	int opt, lfg, sfg, ufg, dfg;
	char *ret, *ext, *p, *k;
	char *larg, *sarg;

	lfg = sfg = ufg = dfg = 0;
	larg = sarg = NULL;
	opterr = 0;
	while ((opt = getopt(argc, argv, "l:s:udh")) != -1) {
		switch (opt) {
		case 'l':
			lfg = 1;
			larg = optarg;
			break;

		case 's':
			sfg = 1;
			sarg = optarg;
			break;

		case 'u':
			ufg = 1;
			break;

		case 'd':
			dfg = 1;
			break;

		case 'h':
			print_usage(EXIT_SUCCESS);

		default:
			errx(EXIT_FAILURE,
			     "error: invalid argument");
	        }
	}

	if (lfg && !sfg) {
		/* -l [lang] [page] */
		if (argv[optind] == NULL)
			 errx(EXIT_FAILURE,
			      "no tldr page name was provided.");
		ext = add_tldr_ext(argv[optind]);
		if (ext == NULL)
			errx(EXIT_FAILURE,
			     "memory allocation failed");

		ret = look_for_tldr(NULL, larg, ext);
		if (ret == NULL)
			errx(EXIT_FAILURE,
			     "nothing was found");
		parse_tldr_file(ret);
		free(ret);
		free(ext);
	} else if (sfg && !lfg) {
		/* argv[optind]: for the tldr page name. */
	        if (argv[optind] == NULL)
			errx(EXIT_FAILURE,
			     "no tldr page xname was provided.");

	        ext = add_tldr_ext(argv[optind]);
		if (ext == NULL)
			errx(EXIT_FAILURE,
			     "memory allocation failed");

	        ret = look_for_tldr(sarg, NULL, ext);
		if (ret == NULL)
			errx(EXIT_FAILURE,
			     "nothing was found");
		parse_tldr_file(ret);
		free(ret);
		free(ext);
	} else if (lfg && sfg) {
		if (argv[optind] == NULL)
			errx(EXIT_FAILURE,
			     "no tldr page name was provided.");
		ext = add_tldr_ext(argv[optind]);
		if (ext == NULL)
			errx(EXIT_FAILURE,
			     "memory allocation failed");

		ret = look_for_tldr(sarg, larg, ext);
		if (ret == NULL)
			errx(EXIT_FAILURE,
			     "nothing was found");
		parse_tldr_file(ret);
		free(ret);
		free(ext);
	} else if (!sfg && !lfg && !ufg && !dfg) {
		if (argv[optind] == NULL)
			errx(EXIT_FAILURE,
			     "no tldr page name was provided.");
		/* [page] */
		ext = add_tldr_ext(argv[optind]);
		if (ext == NULL)
			errx(EXIT_FAILURE,
			     "memory allocation failed");
		ret = look_for_tldr(sarg, larg, ext);
		if (ret == NULL)
			errx(EXIT_FAILURE,
			     "nothing was found");
		parse_tldr_file(ret);
		free(ret);
		free(ext);
	} else if (ufg) {
		p = do_format_zip_path("tldr.zip");
		k = do_format_zip_path(NULL);
		unzip_zip_archive(p, k);
		free(p);
		free(k);
	} else if (dfg) {
		fputs("notice: follow the provided instructions provided below.\n"
		      " * Download the TL;DR ZIP archive: <"ARCHIVE_ZIP_URL">\n"
		      " * Run the following: mkdir -p /home/<username>.mmdr\n"
		      " * Place the ZIP file over to /home/<username>/.mmdr/\n"
		      " * Run the following: mmdr -u (to unzip the archive)\n"
		      " * You're done! Now try, mmdr -s linux apt\n",
		      stdout);
	}
}
