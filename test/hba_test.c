
#include "bouncer.h"

#include <usual/logging.h>
#include <usual/string.h>
#include <usual/time.h>
#include <usual/logging.h>
#include <usual/mbuf.h>
#include <usual/socket.h>
#include <usual/err.h>
#include <usual/event.h>

int cf_tcp_keepcnt;
int cf_tcp_keepintvl;
int cf_tcp_keepidle;
int cf_tcp_keepalive;
int cf_tcp_socket_buffer;
int cf_listen_port;
struct MapList *map_list;


static const char *method2string[] = {
	"trust",
	"x1",
	"x2",
	"password",
	"crypt",
	"md5",
	"creds",
	"cert",
	"peer",
	"hba",
	"reject",
};

static char *get_token(char **ln_p)
{
	char *ln = *ln_p, *tok, *end;

	while (*ln && *ln == '\t') ln++;
	tok = ln;
	while (*ln && *ln != '\t') ln++;
	end = ln;
	while (*ln && *ln == '\t') ln++;

	*ln_p = ln;
	if (tok == end)
		return NULL;
	*end = 0;
	return tok;
}

static int hba_test_eval(struct HBA *hba, char *ln, int linenr)
{
	const char *addr=NULL, *user=NULL, *db=NULL, *tls=NULL, *exp=NULL;
	PgAddr pgaddr;
	int res;

	if (ln[0] == '#')
		return 0;
	exp = get_token(&ln);
	db = get_token(&ln);
	user = get_token(&ln);
	addr = get_token(&ln);
	tls = get_token(&ln);
	if (!exp)
		return 0;
	if (!db || !user)
		die("hbatest: invalid line #%d", linenr);

	if (!pga_pton(&pgaddr, addr, 9999))
		die("hbatest: invalid addr on line #%d", linenr);

	res = hba_eval(hba, &pgaddr, !!tls, db, user);
	if (strcmp(method2string[res], exp) == 0) {
		res = 0;
	} else {
		log_warning("FAIL on line %d: expected '%s' got '%s' - user=%s db=%s addr=%s",
			    linenr, exp, method2string[res], user, db, addr);
		res = 1;
	}
	return res;
}

static void hba_test(void)
{
	struct HBA *hba;
	FILE *f;
	char *ln = NULL;
	size_t lnbuf = 0;
	ssize_t len;
	int linenr;
	int nfailed = 0;
  char *name = "map_ident_test.rules";

	hba = hba_load_rules("hba_test.rules");
  map_list = malloc( sizeof(map_list) );
  map_list = hba_load_map(name);
	if (!hba)
		die("hbatest: did not find config");

	f = fopen("hba_test.eval", "r");
	if (!f)
		die("hbatest: cannot open eval");

	for (linenr = 1; ; linenr++) {
		len = getline(&ln, &lnbuf, f);
		if (len < 0)
			break;
		if (len && ln[len-1] == '\n')
			ln[len-1] = 0;
		nfailed += hba_test_eval(hba, ln, linenr);
	}
	free(ln);
	fclose(f);
	hba_free(hba);
	if (nfailed)
		errx(1, "HBA test failures: %d", nfailed);
	else
		printf("HBA test OK\n");
}

static void hba_map_test(void)
{
  struct List *el;
  struct HBAIdent *map;

  char *name = "map_ident_test.rules";
  map_list = malloc( sizeof(map_list) );
  map_list = hba_load_map(name);

  list_for_each(el, &map_list->maps){
    map = container_of(el, struct HBAIdent, node);
    char *cur_tag = "gui";
    if ( strcmp( map->mapname, cur_tag) == 0 ) {
      continue;
    }
    printf("\nTag : %s",map->mapname);
    printf("\nSys : %s",map->sys_name);
    printf("\nDB  : %s",map->db_name);
    printf("\n");
  }
  return;
}
int main(void)
{
	hba_test();
  hba_map_test();
	return 0;
}

