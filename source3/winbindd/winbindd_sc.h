/*
   Unix SMB/CIFS implementation.

   Winbind smartcard

   Copyright (C) Petr Usoltsev 2025

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define SMARTCARD_SOCKET "/run/samba/winbindd/smartcard"

#define DLIST_FOR_EACH(p, list) for ((p) = (list); (p) != NULL; (p) = (p)->next)

struct cert_auth_info {
	char *user;
	char *cert;
	char *token_name;
	char *module_name;
	char *relative_module_name;
	char *key_id;
	char *label;
	struct cert_auth_info *prev;
	struct cert_auth_info *next;
};

int get_cert_fields(TALLOC_CTX *mem_ctx,
		    const char *query,
		    struct cert_auth_info *cert_fields);

NTSTATUS kerberos_auth_pin(bool forked,
			   TALLOC_CTX *mem_ctx,
			   const char *upn,
			   struct cert_auth_info *fields,
			   const char *pin,
			   int time_offset,
			   const char *cache_name,
			   bool request_pac,
			   uid_t uid,
			   time_t *expire_time,
			   time_t *renew_till_time,
			   char **canon_principal,
			   char **canon_realm);

void sigterm_smartcard(int signum);
void smartcard_do(struct winbindd_domain *domain);
