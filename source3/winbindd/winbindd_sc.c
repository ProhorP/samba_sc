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

#include <openssl/evp.h>
#include <syslog.h>
#include <sys/syscall.h>
#include "includes.h"
#include "ads.h"
#include "winbindd.h"
#include "winbindd_sc.h"

#if !defined(SAMBA4_USES_HEIMDAL) /* MIT version */

#define SYSDB_USER_CERT "userCertificate"
#define SYSDB_NAME "name"
#define SYSDB_PW_ATTRS {SYSDB_NAME, NULL}

#define BUFFER_SIZE 1024

#define SYSDB_USER_CERT_FILTER \
	"(&("                  \
	"objectCategory"       \
	"="                    \
	"user"                 \
	")%s)"

#define SAFE_CLOSE(fd)             \
	do {                       \
		if ((fd) >= 0) {   \
			close(fd); \
			(fd) = -1; \
		}                  \
	} while (0)

static int server_fd = -1;

void sigterm_smartcard(int signum)
{

	SAFE_CLOSE(server_fd);

	unlink(SMARTCARD_SOCKET);

	exit(0);
}

static uint8_t *cert_text(TALLOC_CTX *mem_ctx, size_t *len)
{
	uint8_t *buffer = NULL;
	FILE *fp = NULL;
	const char *command = NULL;

	if (lp_cert_token_name() && strcmp(lp_cert_token_name(), "NONAME") != 0)
	{
		command = talloc_asprintf(mem_ctx,
					  "%s --pre "
					  "--ca_db=%s "
					  "--uri=pkcs11:token=%s --chain-id=3",
					  lp_cert_p11_child(),
					  lp_cert_db_path(),
					  lp_cert_token_name());
	} else {
		command = talloc_asprintf(mem_ctx,
					  "%s --pre "
					  "--ca_db=%s "
					  "--chain-id=3",
					  lp_cert_p11_child(),
					  lp_cert_db_path());
	}
	fp = popen(command, "r");
	if (fp == NULL) {
		DEBUG(0, ("popen failed: %s\n", command));
		goto done;
	}

	size_t buffer_size = 1024;
	buffer = talloc_size(mem_ctx, buffer_size);
	if (!buffer) {
		DEBUG(0, ("talloc_size(mem_ctx, %ld)\n", buffer_size));
		goto done;
	}

	size_t total_read = 0;
	size_t n = 0;
	char temp[512];

	while (fgets(temp, sizeof(temp), fp) != NULL) {
		n = strlen(temp);
		/* check free space */
		if (total_read + n > buffer_size) {
			buffer_size *= 2;
			uint8_t *new_buffer = talloc_realloc_size(mem_ctx,
								  buffer,
								  buffer_size);
			if (!new_buffer) {
				DEBUG(0,
				      ("talloc_realloc_size(mem_ctx, buffer, "
				       "%ld)\n",
				       buffer_size));
				TALLOC_FREE(buffer);
				goto done;
			}
			buffer = new_buffer;
		}
		memcpy(buffer + total_read, temp, n);
		total_read += n;
	}

	*len = total_read;

done:
	if (fp)
		pclose(fp);

	return buffer;
}

static unsigned char *sss_base64_decode(TALLOC_CTX *mem_ctx,
					const char *in,
					size_t *outsize)
{
	unsigned char *outbuf = NULL;
	unsigned char *b64decoded = NULL;
	unsigned char inbuf[512];
	char *in_dup = NULL;
	int size = 0;
	int inlen = strlen(in);
	BIO *bmem = NULL;
	BIO *b64 = NULL;
	BIO *bmem_out = NULL;

	in_dup = talloc_size(mem_ctx, inlen + 1);
	if (!in_dup)
		goto done;
	memcpy(in_dup, in, inlen + 1);

	b64 = BIO_new(BIO_f_base64());
	if (!b64)
		goto done;

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bmem = BIO_new_mem_buf(in_dup, -1);
	if (!bmem) {
		BIO_free(b64);
		goto done;
	}

	b64 = BIO_push(b64, bmem);

	bmem_out = BIO_new(BIO_s_mem());
	if (!bmem_out) {
		BIO_free_all(b64);
		goto done;
	}

	while ((inlen = BIO_read(b64, inbuf, 512)) > 0)
		BIO_write(bmem_out, inbuf, inlen);

	(void)BIO_flush(bmem_out);

	size = BIO_get_mem_data(bmem_out, &b64decoded);

	if (b64decoded) {
		outbuf = talloc_memdup(mem_ctx, b64decoded, size);
		if (!outbuf) {
			BIO_free_all(b64);
			BIO_free(bmem_out);
			goto done;
		}

		*outsize = size;
	} else {
		DEBUG(0, ("Cannot get decoded data\n"));
	}
	BIO_free_all(b64);
	BIO_free(bmem_out);

done:
	return outbuf;
}

static int parse_p11_child_response(TALLOC_CTX *mem_ctx,
				    uint8_t *buf,
				    ssize_t buf_len,
				    struct cert_auth_info **_cert_list)
{
	int ret = 0;
	uint8_t *p = NULL;
	uint8_t *pn = NULL;
	struct cert_auth_info *cert_list = NULL;
	struct cert_auth_info *cert_auth_info = NULL;
	unsigned char *der = NULL;
	size_t der_size = 0;

	if (buf_len <= 0) {
		DEBUG(0,
		      ("Error occurred while reading data from p11_child (len "
		       "= "
		       "%ld)\n",
		       buf_len));
		return EIO;
	}

	p = memchr(buf, '\n', buf_len);
	if ((p == NULL) || (p == buf)) {
		DEBUG(0, ("Missing status in p11_child response.\n"));
		return EINVAL;
	}
	errno = 0;
	ret = strtol((char *)buf, (char **)&pn, 10);
	if ((errno != 0) || (pn == buf)) {
		DEBUG(0, ("Invalid status in p11_child response.\n"));
		return EINVAL;
	}

	if (ret != 0) {
		*_cert_list = NULL;
		return ret; /* other errors are treated as "no cert
			       found" */
	}

	if ((p - buf + 1) == buf_len) {
		DEBUG(5, ("No certificate found.\n"));
		*_cert_list = NULL;
		return 0;
	}

	p++;

	do {
		cert_auth_info = talloc_zero(mem_ctx, struct cert_auth_info);
		if (cert_auth_info == NULL) {
			DEBUG(0, ("talloc_zero failed.\n"));
			ret = ENOMEM;
			goto done;
		}

		pn = memchr(p, '\n', buf_len - (p - buf));
		if (pn == NULL) {
			DEBUG(0, ("Missing new-line in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}
		if (pn == p) {
			DEBUG(0,
			      ("Missing token name in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		cert_auth_info->token_name = talloc_strndup(cert_auth_info,
							    (char *)p,
							    (pn - p));
		if (cert_auth_info->token_name == NULL) {
			DEBUG(0, ("talloc_strndup failed.\n"));
			ret = ENOMEM;
			goto done;
		}
		DEBUG(10,
		      ("Found token name [%s].\n", cert_auth_info->token_name));

		p = ++pn;
		pn = memchr(p, '\n', buf_len - (p - buf));
		if (pn == NULL) {
			DEBUG(0, ("Missing new-line in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		if (pn == p) {
			DEBUG(0,
			      ("Missing module name in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		cert_auth_info->module_name = talloc_strndup(cert_auth_info,
							     (char *)p,
							     (pn - p));
		if (cert_auth_info->module_name == NULL) {
			DEBUG(0, ("talloc_strndup failed.\n"));
			ret = ENOMEM;
			goto done;
		}
		DEBUG(10,
		      ("Found module name [%s].\n",
		       cert_auth_info->module_name));

		p = ++pn;
		pn = memchr(p, '\n', buf_len - (p - buf));
		if (pn == NULL) {
			DEBUG(0, ("Missing new-line in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		if (pn == p) {
			DEBUG(0, ("Missing key id in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		cert_auth_info->key_id = talloc_strndup(cert_auth_info,
							(char *)p,
							(pn - p));
		if (cert_auth_info->key_id == NULL) {
			DEBUG(0, ("talloc_strndup failed.\n"));
			ret = ENOMEM;
			goto done;
		}
		DEBUG(10, ("Found key id [%s].\n", cert_auth_info->key_id));

		p = ++pn;
		pn = memchr(p, '\n', buf_len - (p - buf));
		if (pn == NULL) {
			DEBUG(0, ("Missing new-line in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		if (pn == p) {
			DEBUG(0, ("Missing label in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		cert_auth_info->label = talloc_strndup(cert_auth_info,
						       (char *)p,
						       (pn - p));
		if (cert_auth_info->label == NULL) {
			DEBUG(0, ("talloc_strndup failed.\n"));
			ret = ENOMEM;
			goto done;
		}
		DEBUG(10, ("Found label [%s].\n", cert_auth_info->label));

		p = ++pn;
		pn = memchr(p, '\n', buf_len - (p - buf));
		if (pn == NULL) {
			DEBUG(0, ("Missing new-line in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		if (pn == p) {
			DEBUG(0, ("Missing cert in p11_child response.\n"));
			ret = EINVAL;
			goto done;
		}

		cert_auth_info->cert = talloc_strndup(cert_auth_info,
						      (char *)p,
						      (pn - p));
		if (cert_auth_info->cert == NULL) {
			DEBUG(0, ("talloc_strndup failed.\n"));
			ret = ENOMEM;
			goto done;
		}
		DEBUG(10, ("Found cert [%s].\n", cert_auth_info->cert));

		der = sss_base64_decode(mem_ctx,
					cert_auth_info->cert,
					&der_size);
		if (der == NULL) {
			DEBUG(0, ("sss_base64_decode failed.\n"));
			ret = EIO;
			goto done;
		}

		DLIST_ADD(cert_list, cert_auth_info);

		p = ++pn;
	} while ((pn - buf) < buf_len);

	ret = 0;

done:
	if (ret == 0)
		*_cert_list = cert_list;

	return ret;
}

static int bin_to_ldap_filter_value(TALLOC_CTX *mem_ctx,
				    const uint8_t *blob,
				    size_t blob_size,
				    char **_str)
{
	int ret = 0;
	size_t c = 0;
	size_t len = 0;
	char *str = NULL;
	char *p = 0;

	if (blob == NULL || blob_size == 0 || _str == NULL) {
		DEBUG(0, ("Missing input parameter.\n"));
		return EINVAL;
	}

	len = (blob_size * 3) + 1;
	str = talloc_size(mem_ctx, len);
	if (str == NULL) {
		DEBUG(0, ("talloc_size failed.\n"));
		return ENOMEM;
	}
	str[len - 1] = '\0';

	p = str;
	for (c = 0; c < blob_size; c++) {
		ret = snprintf(p, 4, "\\%02x", blob[c]);
		if (ret != 3) {
			DEBUG(0, ("snprintf failed.\n"));
			ret = EIO;
			goto done;
		}

		p += 3;
	}

	ret = 0;

done:
	if (ret == 0) {
		*_str = str;
	} else {
		talloc_free(str);
	}

	return ret;
}

static int sysdb_cert_derb64_to_ldap_filter(TALLOC_CTX *mem_ctx,
					    const char *derb64,
					    const char *attr_name,
					    char **ldap_filter)
{
	int ret = 0;
	unsigned char *der = NULL;
	size_t der_size = 0;
	char *val = NULL;

	if (derb64 == NULL || attr_name == NULL) {
		return EINVAL;
	}

	der = sss_base64_decode(mem_ctx, derb64, &der_size);
	if (der == NULL) {
		DEBUG(0, ("sss_base64_decode failed.\n"));
		return EINVAL;
	}

	ret = bin_to_ldap_filter_value(mem_ctx, der, der_size, &val);
	talloc_free(der);
	if (ret != 0) {
		DEBUG(0, ("bin_to_ldap_filter_value failed.\n"));
		return ret;
	}

	*ldap_filter = talloc_asprintf(mem_ctx, "(%s=%s)", attr_name, val);
	talloc_free(val);
	if (*ldap_filter == NULL) {
		DEBUG(0, ("talloc_asprintf failed.\n"));
		return ENOMEM;
	}

	return 0;
}

ADS_STATUS ads_cached_connection_ldap(struct winbindd_domain *domain,
				      ADS_STRUCT **adsp);

#if (0)
static void ads_process_results_1(ADS_STRUCT *ads, LDAPMessage *res)
{
	LDAPMessage *msg;
	TALLOC_CTX *ctx;
	size_t converted_size;

	if (!(ctx = talloc_init("ads_process_results")))
		return;

	for (msg = ads_first_entry(ads, res); msg;
	     msg = ads_next_entry(ads, msg))
	{
		char *utf8_field;
		BerElement *b;

		for (utf8_field = ldap_first_attribute(ads->ldap.ld,
						       (LDAPMessage *)msg,
						       &b);
		     utf8_field;
		     utf8_field = ldap_next_attribute(ads->ldap.ld,
						      (LDAPMessage *)msg,
						      b))
		{
			struct berval **ber_vals;
			char *field;

			if (!pull_utf8_talloc(
				    ctx, &field, utf8_field, &converted_size))
			{
				DEBUG(0,
				      ("ads_process_results: "
				       "pull_utf8_talloc failed: %s",
				       strerror(errno)));
			}

			ber_vals = ldap_get_values_len(ads->ldap.ld,
						       (LDAPMessage *)msg,
						       field);

			syslog(LOG_ERR,
			       "!!!!LDAP!!! attr=%s, value=%.*s",
			       field,
			       (int)(*ber_vals)->bv_len,
			       (*ber_vals)->bv_val);

			ldap_value_free_len(ber_vals);
			ldap_memfree(utf8_field);
		}
		ber_free(b, 0);
		talloc_free_children(ctx);
	}
	talloc_destroy(ctx);
}
#endif

static int winbind_ldap_get_user_by_cert(struct winbindd_domain *domain,
					 const char *filter,
					 const char **attrs,
					 struct cert_auth_info *res)
{
	int ret = 0;
	LDAPMessage *msg = NULL;
	ADS_STRUCT *ads = NULL;
	ADS_STATUS rc = {0};

	if (!winbindd_can_contact_domain(domain)) {
		DEBUG(10,("winbind_ldap_get_user_by_cert: No incoming trust for domain %s\n",
domain->name));
		ret = -1;
		goto out;
	}

	/* We set the caching time to 1970(Beginning Unix time) */

	if (domain->backend_data.ads_conn) {
		static const struct timeval tv1970;
		domain->backend_data.ads_conn->auth
			.expire_time = timeval_to_nttime(&tv1970);
	}
	rc = ads_cached_connection_ldap(domain, &ads);
	if (!ADS_ERR_OK(rc)) {
		domain->last_status = NT_STATUS_SERVER_DISABLED;
		DEBUG(5, ("sid_to_name LDAP: not connect to LDAP server!\n"));
		ret = -1;
		goto out;
	}

	rc = ads_search(ads, &msg, filter, attrs);
	int count = 0;
	if (ADS_ERR_OK(rc))
		if ((count = ads_count_replies(ads, msg)) != 1)
			rc = ADS_ERROR_LDAP(LDAP_NO_SUCH_OBJECT);

	if (!ADS_ERR_OK(rc)) {
		DEBUG(5, ("user_by_cert LDAP: Failed to find %s\n", filter));
		ret = -1;
		goto out;
	}

	/* ads_process_results_1(ads, msg); */
	if ((res->user = ads_pull_string(ads, res, msg, SYSDB_NAME)) == NULL) {
		DEBUG(5, ("user_by_cert LDAP: No name attribute!\n"));
		ret = -1;
		goto out;
	}

out:
	ads_msgfree(ads, msg);

	return ret;
}

static int sysdb_search_object_by_cert(struct winbindd_domain *domain,
				       const char *cert,
				       const char **attrs,
				       struct cert_auth_info *res)
{
	int ret = 0;
	char *user_filter = NULL;
	char *filter = NULL;

	ret = sysdb_cert_derb64_to_ldap_filter(res,
					       cert,
					       SYSDB_USER_CERT,
					       &user_filter);
	if (ret != 0) {
		DEBUG(0, ("sss_cert_derb64_to_ldap_filter failed.\n"));
		return ret;
	}

	filter = talloc_asprintf(NULL, SYSDB_USER_CERT_FILTER, user_filter);
	talloc_free(user_filter);
	if (filter == NULL) {
		return ENOMEM;
	}

	ret = winbind_ldap_get_user_by_cert(domain, filter, attrs, res);

	talloc_free(filter);

	return ret;
}

static int sysdb_search_user_by_cert(struct winbindd_domain *domain,
				     const char *cert,
				     struct cert_auth_info *res)
{
	const char *user_attrs[] = SYSDB_PW_ATTRS;

	return sysdb_search_object_by_cert(domain, cert, user_attrs, res);
}

static int write_and_check(int fd, const char *buffer, size_t size)
{
	int ret = 0;

	ssize_t bytes_write = write(fd, buffer, size);

	if (bytes_write != size) {
		DEBUG(0, ("write %ld of %ld'\n", bytes_write, size));
		ret = -1;
		goto done;
	}

done:
	return ret;
}

int get_cert_fields(TALLOC_CTX *mem_ctx,
		    const char *query,
		    struct cert_auth_info *cert_fields)
{

	int ret = 0;
	int client_fd = -1;
	struct sockaddr_un server_addr = {0};
	char buffer[BUFFER_SIZE];

	if ((client_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		DEBUG(0, ("socket failed %d\n", client_fd));
		ret = -1;
		goto done;
	}

	memset(&server_addr, 0, sizeof(struct sockaddr_un));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path,
		SMARTCARD_SOCKET,
		sizeof(server_addr.sun_path) - 1);

	if (connect(client_fd,
		    (struct sockaddr *)&server_addr,
		    sizeof(struct sockaddr_un)) == -1)
	{
		DEBUG(0, ("connect failed %d\n", -1));
		ret = -1;
		goto done;
	}

	if (write_and_check(client_fd, query, strlen(query)) < 0) {
		DEBUG(0, ("write in smartcard soket failed \n"));
		ret = -1;
		goto done;
	}

	ssize_t bytes_received = read(client_fd, buffer, sizeof(buffer) - 1);
	if (bytes_received > 0) {
		buffer[bytes_received] = '\0';

		const char *error_text = "user not found";
		if (strlen(error_text) == bytes_received &&
		    memcmp(error_text, buffer, bytes_received) == 0)
		{
			DEBUG(0, ("current message = %s\n", buffer));
			ret = -1;
			goto done;
		}

		char *relative_module_name = strchr(buffer, '\n');
		if (relative_module_name == NULL) {
			DEBUG(0,
			      ("invalid format. current message = %s\n",
			       buffer));
			ret = -1;
			goto done;
		}
		if (relative_module_name) {
			*relative_module_name = '\0';
			relative_module_name++;
		}

		cert_fields->token_name = talloc_strdup(mem_ctx, buffer);
		cert_fields->relative_module_name = talloc_strdup(
			mem_ctx, relative_module_name);
	} else {
		DEBUG(0, ("read from smartcard soket failed %d\n", -1));
		ret = -1;
		goto done;
	}

done:
	SAFE_CLOSE(client_fd);

	return ret;
}

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
			   char **canon_realm)
{

	int ret = 0;

	TALLOC_CTX *frame = talloc_stackframe();
	if (!frame) {
		DEBUG(0, ("talloc_new fail\n"));
		ret = -1;
		goto done;
	}

	/* Kerberos auth */
	char *identity = talloc_asprintf(frame,
					 "PKCS11:%s:token=%s",
					 fields->relative_module_name,
					 fields->token_name);

	if (!identity) {
		DEBUG(0, ("talloc_asprintf fail\n"));
		ret = -1;
		goto done;
	}

	/* krb5 auth smart card */
	if (forked) {

		int pipefd[2];

		ret = pipe(pipefd);
		if (ret == -1) {
			ret = errno;
			DEBUG(0,
			      ("pipe failed [%d][%s].\n", ret, strerror(ret)));
			goto done;
		}

		pid_t pid = fork();

		if (pid == 0) {
			/* Child */

			close(pipefd[0]); /* close read */

			time_t _expire_time = 0;
			time_t _renew_till_time = 0;
			char *_canon_principal = NULL;
			char *_canon_realm = NULL;

			ret = kerberos_kinit_pin_ext(
				frame,
				upn,
				pin,
				time_offset,
				identity,
				cache_name,
				request_pac,
				uid,
				WINBINDD_PAM_AUTH_KRB5_RENEW_TIME,
				&_expire_time,
				&_renew_till_time,
				&_canon_principal,
				&_canon_realm);

			if (ret == 0) {
				dprintf(pipefd[1],
					"%ld;%ld;%s;%s;",
					_expire_time,
					_renew_till_time,
					_canon_principal,
					_canon_realm);
			} else {
				dprintf(pipefd[1], "fail ret = %d", ret);
			}

			close(pipefd[1]); /* close write */

			TALLOC_FREE(frame);
			exit(ret);
		} else {
			/* Parent */
			close(pipefd[1]); /* close write */

			/******************************/
			char *buffer = NULL;

			size_t buffer_size = 1024;
			buffer = talloc_size(frame, buffer_size);
			if (!buffer) {
				DEBUG(0,
				      ("talloc_size(frame, %ld)\n",
				       buffer_size));
				goto done;
			}

			size_t total_read = 0;
			size_t n = 0;
			char temp[512];

			while ((n = read(pipefd[0], temp, sizeof(temp))) > 0) {
				/* check free space */
				if (total_read + n > buffer_size) {
					buffer_size *= 2;
					char *new_buffer = talloc_realloc_size(
						frame, buffer, buffer_size);
					if (!new_buffer) {
						DEBUG(0,
						      ("talloc_realloc_size("
						       "frame, "
						       "buffer, "
						       "%ld)\n",
						       buffer_size));
						TALLOC_FREE(buffer);
						goto done;
					}
					buffer = new_buffer;
				}
				memcpy(buffer + total_read, temp, n);
				total_read += n;
			}

			/************************************/

			close(pipefd[0]); /* close read */

			int status = 0;
			waitpid(pid, &status, 0);

			if (WIFEXITED(status)) {
				int exit_code = WEXITSTATUS(status);
				if (exit_code == 0) {
					time_t _expire_time = 0;
					time_t _renew_till_time = 0;
					char *_canon_principal = NULL;
					char *_canon_realm = NULL;

					char *ptr = buffer;
					char *pn = ptr;

					_expire_time = strtol((char *)ptr,
							      (char **)&pn,
							      10);
					if (pn == ptr) {
						DEBUG(0,
						      ("Invalid expire_time in "
						       "pipe\n"));
						ret = EINVAL;
						goto done;
					}
					ptr = pn + 1;
					pn = ptr;

					_renew_till_time = strtol((char *)ptr,
								  (char **)&pn,
								  10);
					if (pn == ptr) {
						DEBUG(0,
						      ("Invalid "
						       "renew_till_time in "
						       "pipe\n"));
						ret = EINVAL;
						goto done;
					}
					ptr = pn + 1;
					pn = ptr;

					char *end_line = strchr(ptr, ';');
					_canon_principal = talloc_strndup(
						mem_ctx, ptr, end_line - ptr);
					if (_canon_principal == NULL) {
						DEBUG(0, ("talloc_strndup\n"));
						ret = ENOMEM;
						goto done;
					}

					ptr = end_line + 1;

					end_line = strchr(ptr, ';');
					_canon_realm = talloc_strndup(
						mem_ctx, ptr, end_line - ptr);
					if (_canon_realm == NULL) {
						DEBUG(0, ("talloc_strndup\n"));
						ret = ENOMEM;
						goto done;
					}

					*expire_time = _expire_time;
					*renew_till_time = _renew_till_time;
					*canon_principal = _canon_principal;
					*canon_realm = _canon_realm;

					ret = 0;
				} else {
					DEBUG(0,
					      ("krb5 auth %s fail\n",
					       identity));
					ret = -1;
				}
			} else {
				DEBUG(0, ("krb5 auth %s fail\n", identity));
				ret = -1;
			}
		}

	} else {

		/* if not forked */
		time_t _expire_time = 0;
		time_t _renew_till_time = 0;
		char *_canon_principal = NULL;
		char *_canon_realm = NULL;

		ret = kerberos_kinit_pin_ext(mem_ctx,
					     upn,
					     pin,
					     time_offset,
					     identity,
					     cache_name,
					     request_pac,
					     uid,
					     WINBINDD_PAM_AUTH_KRB5_RENEW_TIME,
					     &_expire_time,
					     &_renew_till_time,
					     &_canon_principal,
					     &_canon_realm);

		if (ret == 0) {

			*expire_time = _expire_time;
			*renew_till_time = _renew_till_time;
			*canon_principal = _canon_principal;
			*canon_realm = _canon_realm;
		}
	}

done:
	TALLOC_FREE(frame);

	if (ret == 0)
		return NT_STATUS_OK;
	else
		return NT_STATUS_UNSUCCESSFUL;
}

static NTSTATUS check_cert(TALLOC_CTX *mem_ctx,
			   struct winbindd_domain *domain,
			   const char *user,
			   struct cert_auth_info **cert_list)
{

	int ret = 0;

	TALLOC_CTX *frame = talloc_stackframe();
	if (!frame) {
		DEBUG(0, ("talloc_new fail\n"));
		ret = -1;
		goto done;
	}

	/* get info by smart card */
	size_t buf_len = 0;
	uint8_t *buf = cert_text(frame, &buf_len);

	if ((ret = parse_p11_child_response(
		     mem_ctx, buf, buf_len, cert_list)) != 0)
		goto done;

	if (*cert_list == NULL) {
		ret = -1;
		goto done;
	}

	/* LDAP query: find user by cert */
	if ((ret = sysdb_search_user_by_cert(domain,
					     (*cert_list)->cert,
					     *cert_list)) != 0)
		goto done;

	/* if user == cert.user -> auth kerberos */
	if (strcmp((*cert_list)->user, user) != 0) {
		ret = -1;
		goto done;
	}

	/* we get the name after the last separator */
	char *ptr = (*cert_list)->module_name;
	char *ptr_last = NULL;
	do {
		ptr++;
		ptr_last = ptr;
	} while ((ptr = strchr(ptr, '/')) != NULL);

	if (ptr_last) {
		(*cert_list)->relative_module_name = talloc_strdup((*cert_list),
								   ptr_last);
	}

done:

	TALLOC_FREE(frame);

	if (ret == 0)
		return NT_STATUS_OK;
	else
		return NT_STATUS_UNSUCCESSFUL;
}

void smartcard_do(struct winbindd_domain *domain)
{

	int ret = 0;
	server_fd = -1;
	int client_fd = -1;
	struct sockaddr_un server_addr = {0};
	struct cert_auth_info *cert_list = NULL;

	TALLOC_CTX *frame = talloc_stackframe();
	if (!frame) {
		DEBUG(0, ("talloc_new fail\n"));
		ret = -1;
		goto done;
	}

	if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		DEBUG(0, ("socket return %d\n", server_fd));
		ret = -1;
		goto done;
	}

	/* configuring the server address */
	memset(&server_addr, 0, sizeof(struct sockaddr_un));
	server_addr.sun_family = AF_UNIX;
	strncpy(server_addr.sun_path,
		SMARTCARD_SOCKET,
		sizeof(server_addr.sun_path) - 1);

	/* binding a socket to a file */
	if (bind(server_fd,
		 (struct sockaddr *)&server_addr,
		 sizeof(struct sockaddr_un)) == -1)
	{
		DEBUG(0, ("bind error\n"));
		ret = -1;
		goto done;
	}

	/* we give everyone access */
	chmod(SMARTCARD_SOCKET, 0777);

	if (listen(server_fd, 5) == -1) {
		DEBUG(0, ("listen failed\n"));
		ret = -1;
		goto done;
	}

	while (1) {

		struct cert_auth_info *cert_auth = NULL;
		bool find_user = false;
		bool direct_find = false;

		/* we accept the connection from the client */
		client_fd = accept(server_fd, NULL, NULL);
		if (client_fd == -1) {
			DEBUG(0, ("accept failed\n"));
			continue;
		}

		char buffer[BUFFER_SIZE];
		ssize_t bytes_read = 0;

		if ((bytes_read = read(client_fd, buffer, sizeof(buffer) - 1)) <
		    1)
		{
			DEBUG(0, ("read return '%ld'\n", bytes_read));
			continue;
		}

		if (buffer[bytes_read - 1] == '\n')
			buffer[bytes_read - 1] = '\0';
		else
			buffer[bytes_read] = '\0';

		/* if query "get user" - get token direct */
		const char *ptr = NULL;
		if ((ptr = strchr(buffer, ' ')) && (ptr - 3 == buffer) &&
		    (strncmp(buffer, "get", 3) == 0))
		{
			memcpy(buffer, buffer + 4, strlen(buffer) - 3);
			direct_find = true;
		}

		DLIST_FOR_EACH(cert_auth, cert_list)
		{
			if (strcmp(cert_auth->user, buffer) == 0) {
				find_user = true;
				break;
			}
		}

		if (find_user) {
			if (direct_find) {
				DLIST_REMOVE(cert_list, cert_auth);
				TALLOC_FREE(cert_auth);
			}
		} else {
			cert_auth = NULL;
		}

		DEBUG(0, ("accept query %s\n", buffer));

		if (cert_auth) {
			if (direct_find) {
				snprintf(buffer,
					 sizeof(buffer),
					 "%s",
					 cert_auth->token_name);
			} else {
				snprintf(buffer,
					 sizeof(buffer),
					 "%s\n%s",
					 cert_auth->token_name,
					 cert_auth->relative_module_name);
			}

			if (write_and_check(client_fd, buffer, strlen(buffer)) <
			    0)
				continue;

		} else if (NT_STATUS_IS_OK(check_cert(
				   frame, domain, buffer, &cert_auth)))
		{

			/* save cache */
			DLIST_ADD(cert_list, cert_auth);

			if (direct_find) {
				snprintf(buffer,
					 sizeof(buffer),
					 "%s",
					 cert_auth->token_name);
			} else {
				snprintf(buffer,
					 sizeof(buffer),
					 "%s\n%s",
					 cert_auth->token_name,
					 cert_auth->relative_module_name);
			}

			if (write_and_check(client_fd, buffer, strlen(buffer)) <
			    0)
				continue;
		} else {
			TALLOC_FREE(cert_auth);
			snprintf(buffer,
				 sizeof(buffer),
				 "%s",
				 "user not found");

			if (write_and_check(client_fd, buffer, strlen(buffer)) <
			    0)
				continue;
		}

		SAFE_CLOSE(client_fd);
	}

done:
	/* shutting down the server */
	SAFE_CLOSE(client_fd);
	SAFE_CLOSE(server_fd);

	unlink(SMARTCARD_SOCKET);

	TALLOC_FREE(frame);

	exit(ret);
}
#endif /* MIT version */
