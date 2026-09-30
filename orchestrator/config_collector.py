import argparse
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


class TomcatConfigCollector:
    """
    CVE-agnostic Tomcat configuration collector.

    The collector gathers security-relevant environmental and configuration evidence
    across Tomcat's server, container, application, connector, and runtime boundaries.

    The collector does NOT determine CVE exploitability, severity, or remediation.
    It extracts objective, structured evidence distinguishing between explicit configuration,
    Tomcat defaults, and runtime detections.
    """

    def __init__(self, container_name):
        self.container_name = container_name

    def docker_exec(self, command):
        """
        Execute command inside the target Docker container safely.
        """
        result = subprocess.run(
            [
                "docker",
                "exec",
                self.container_name,
                "sh",
                "-c",
                command
            ],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            return ""

        return result.stdout

    # ---------------------------------------------------------
    # SECRETS REDACTION & ATTRIBUTE HELPERS
    # ---------------------------------------------------------

    @staticmethod
    def redact_secrets_in_text(text):
        """
        Redact sensitive attributes such as passwords, keystore secrets,
        or private keys from raw configuration strings.
        """
        if not text:
            return ""

        patterns = [
            (
                r'((?:password|certificateKeystorePassword|certificateKeyPassword|'
                r'truststorePassword|secret|keyPass|storePass)\s*=\s*")[^"]*(")',
                r'\1[REDACTED]\2'
            ),
            (
                r"((?:password|certificateKeystorePassword|certificateKeyPassword|"
                r"truststorePassword|secret|keyPass|storePass)\s*=\s*')[^']*(')",
                r"\1[REDACTED]\2"
            )
        ]

        sanitized = text
        for pat, rep in patterns:
            sanitized = re.sub(pat, rep, sanitized, flags=re.IGNORECASE)

        return sanitized

    @staticmethod
    def extract_attributes(tag_string):
        """
        Extract XML attributes from a tag string into a dictionary,
        redacting any secret attribute values.
        """
        attrs = {}
        for match in re.finditer(r'([a-zA-Z0-9_\.:-]+)\s*=\s*"([^"]*)"', tag_string):
            key = match.group(1)
            val = match.group(2)
            key_lower = key.lower()

            if any(s in key_lower for s in ["password", "secret", "keypass", "storepass", "privatekey"]):
                attrs[key] = "[REDACTED]" if val else ""
            else:
                attrs[key] = val

        return attrs

    # ---------------------------------------------------------
    # BASIC INFORMATION
    # ---------------------------------------------------------

    def get_tomcat_version(self):
        """
        Collect exact Tomcat version and runtime environmental information.
        """
        output = self.docker_exec(
            "/opt/tomcat/bin/version.sh 2>/dev/null"
        )

        version = None
        match = re.search(
            r"Server version:\s+Apache Tomcat/([^\s]+)",
            output
        )
        if match:
            version = match.group(1)

        server_built = None
        match_built = re.search(r"Server built:\s+([^\r\n]+)", output)
        if match_built:
            server_built = match_built.group(1).strip()

        server_number = None
        match_num = re.search(r"Server number:\s+([^\r\n]+)", output)
        if match_num:
            server_number = match_num.group(1).strip()

        os_name = None
        match_os = re.search(r"OS Name:\s+([^\r\n]+)", output)
        if match_os:
            os_name = match_os.group(1).strip()

        os_version = None
        match_osv = re.search(r"OS Version:\s+([^\r\n]+)", output)
        if match_osv:
            os_version = match_osv.group(1).strip()

        arch = None
        match_arch = re.search(r"Architecture:\s+([^\r\n]+)", output)
        if match_arch:
            arch = match_arch.group(1).strip()

        jvm_version = None
        match_jvm = re.search(r"JVM Version:\s+([^\r\n]+)", output)
        if match_jvm:
            jvm_version = match_jvm.group(1).strip()

        jvm_vendor = None
        match_jv = re.search(r"JVM Vendor:\s+([^\r\n]+)", output)
        if match_jv:
            jvm_vendor = match_jv.group(1).strip()

        return {
            "version": version,
            "server_built": server_built,
            "server_number": server_number,
            "os_name": os_name,
            "os_version": os_version,
            "architecture": arch,
            "jvm_version": jvm_version,
            "jvm_vendor": jvm_vendor,
            "catalina_home": "/opt/tomcat",
            "raw": output.strip()
        }

    # ---------------------------------------------------------
    # RAW CONFIGURATION FILES
    # ---------------------------------------------------------

    def get_file(self, path):
        """
        Retrieve raw file content from container with secrets redacted.
        """
        output = self.docker_exec(
            f"cat {path} 2>/dev/null"
        )

        sanitized_content = self.redact_secrets_in_text(output)

        return {
            "path": path,
            "content": sanitized_content
        }

    # ---------------------------------------------------------
    # XML HELPERS
    # ---------------------------------------------------------

    def remove_xml_comments(self, content):
        """
        Remove XML comments before analysing active configuration.

        This prevents commented-out configuration from being treated as active.
        """
        if not content:
            return ""

        return re.sub(
            r"<!--.*?-->",
            "",
            content,
            flags=re.DOTALL
        )

    def get_param(self, xml, parameter_name):
        """
        Extract:
        <param-name>NAME</param-name>
        <param-value>VALUE</param-value>

        Returns None if not explicitly configured.
        """
        if not xml or not parameter_name:
            return None

        pattern = (
            r"<param-name>\s*"
            + re.escape(parameter_name)
            + r"\s*</param-name>\s*"
            r"<param-value>\s*([^<]+?)\s*</param-value>"
        )

        match = re.search(
            pattern,
            xml,
            flags=re.IGNORECASE
        )

        if not match:
            return None

        return match.group(1).strip()

    # ---------------------------------------------------------
    # DEFAULT SERVLET
    # ---------------------------------------------------------

    def get_default_servlet_effective_config(self, web_xml):
        """
        Extract DefaultServlet parameters and derive effective values
        distinguishing explicit configuration from Tomcat defaults.
        """
        active_xml = self.remove_xml_comments(web_xml)

        readonly = self.get_param(
            active_xml,
            "readonly"
        )

        allow_partial_put = self.get_param(
            active_xml,
            "allowPartialPut"
        )

        listings = self.get_param(
            active_xml,
            "listings"
        )

        debug = self.get_param(
            active_xml,
            "debug"
        )

        file_encoding = self.get_param(
            active_xml,
            "fileEncoding"
        )

        show_server_info = self.get_param(
            active_xml,
            "showServerInfo"
        )

        # Tomcat DefaultServlet defaults
        if readonly is None:
            effective_readonly = True
            readonly_source = "Tomcat default"
        else:
            effective_readonly = readonly.lower() == "true"
            readonly_source = "explicit configuration"

        # Tomcat 9 DefaultServlet allowPartialPut defaults to true
        if allow_partial_put is None:
            effective_partial_put = True
            partial_put_source = "Tomcat default"
        else:
            effective_partial_put = allow_partial_put.lower() == "true"
            partial_put_source = "explicit configuration"

        # listings default is false in shipped Tomcat configuration
        if listings is None:
            effective_listings = False
            listings_source = "Tomcat default"
        else:
            effective_listings = listings.lower() == "true"
            listings_source = "explicit configuration"

        config = {
            "readonly": effective_readonly,
            "readonly_source": readonly_source,

            "writes_enabled": not effective_readonly,

            "allowPartialPut": effective_partial_put,
            "allowPartialPut_source": partial_put_source,

            "listings": effective_listings,
            "listings_source": listings_source
        }

        if debug is not None:
            config["debug"] = debug
            config["debug_source"] = "explicit configuration"

        if file_encoding is not None:
            config["fileEncoding"] = file_encoding
            config["fileEncoding_source"] = "explicit configuration"

        if show_server_info is not None:
            config["showServerInfo"] = show_server_info.lower() == "true"
            config["showServerInfo_source"] = "explicit configuration"

        return config

    # ---------------------------------------------------------
    # SESSION PERSISTENCE
    # ---------------------------------------------------------

    def get_session_persistence(self, context_xml):
        """
        Analyze session Manager configuration and persistence mechanism.
        """
        active_xml = self.remove_xml_comments(context_xml)

        manager_match = re.search(
            r"<Manager\b([^>]*)/?>",
            active_xml,
            flags=re.IGNORECASE
        )

        # No active Manager configuration
        if not manager_match:
            return {
                "manager_configured": False,
                "manager_class": "org.apache.catalina.session.StandardManager",
                "pathname": "SESSIONS.ser",
                "file_based_persistence": True,
                "persistence_source": "Tomcat default"
            }

        manager_attributes = manager_match.group(1)

        class_match = re.search(
            r'className\s*=\s*"([^"]+)"',
            manager_attributes,
            flags=re.IGNORECASE
        )

        pathname_match = re.search(
            r'pathname\s*=\s*"([^"]*)"',
            manager_attributes,
            flags=re.IGNORECASE
        )

        manager_class = (
            class_match.group(1)
            if class_match
            else "org.apache.catalina.session.StandardManager"
        )

        if pathname_match:
            pathname = pathname_match.group(1)
            file_based = pathname != ""
            source = "explicit configuration"
        else:
            pathname = "SESSIONS.ser"
            file_based = True
            source = "Tomcat default"

        return {
            "manager_configured": True,
            "manager_class": manager_class,
            "pathname": pathname,
            "file_based_persistence": file_based,
            "persistence_source": source
        }

    # ---------------------------------------------------------
    # APPLICATIONS & LIBRARIES
    # ---------------------------------------------------------

    def get_deployed_apps(self):
        """
        List top-level directories deployed under /opt/tomcat/webapps.
        """
        output = self.docker_exec(
            """
            find /opt/tomcat/webapps \
            -mindepth 1 \
            -maxdepth 1 \
            -type d \
            -printf '%f\\n' 2>/dev/null
            """
        )

        return [
            item.strip()
            for item in output.splitlines()
            if item.strip()
        ]

    def get_application_jars(self):
        """
        List all JAR files located under deployed applications' WEB-INF/lib.
        """
        output = self.docker_exec(
            """
            find /opt/tomcat/webapps \
            -type f \
            -path '*/WEB-INF/lib/*.jar' \
            -printf '%p\\n' 2>/dev/null
            """
        )

        return [
            item.strip()
            for item in output.splitlines()
            if item.strip()
        ]

    def get_server_jars(self):
        """
        List all common/server-level JAR files located in /opt/tomcat/lib.
        """
        output = self.docker_exec(
            """
            find /opt/tomcat/lib \
            -maxdepth 1 \
            -type f \
            -name '*.jar' \
            -printf '%f\\n' 2>/dev/null
            """
        )

        return [
            item.strip()
            for item in output.splitlines()
            if item.strip()
        ]

    def parse_jar_details(self, jar_paths):
        """
        Parse structured jar details without guessing ambiguous versions.
        """
        details = []
        version_pattern = re.compile(
            r"^(.+?)-(\d+(?:\.\d+)*(?:[-_\.][a-zA-Z0-9]+)*)\.jar$",
            re.IGNORECASE
        )

        for jar_path in jar_paths:
            filename = Path(jar_path).name
            app_match = re.search(r"/webapps/([^/]+)/", jar_path)
            app_name = app_match.group(1) if app_match else None

            match = version_pattern.match(filename)
            if match:
                name = match.group(1)
                version = match.group(2)
            else:
                name = filename.rsplit(".jar", 1)[0]
                version = None

            details.append({
                "path": jar_path,
                "filename": filename,
                "name": name,
                "version": version,
                "application": app_name
            })

        return details

    # ---------------------------------------------------------
    # CONNECTORS
    # ---------------------------------------------------------

    def get_connectors(self, server_xml):
        """
        Extract all active connectors and their parameters from server.xml.
        """
        active_xml = self.remove_xml_comments(server_xml)
        connectors = []

        for match in re.finditer(
            r"<Connector\b([^>]*)/?>",
            active_xml,
            flags=re.IGNORECASE
        ):
            attributes_str = match.group(1)
            attrs = self.extract_attributes(attributes_str)

            port = attrs.get("port")
            protocol = attrs.get("protocol")

            if port:
                ssl_enabled_attr = attrs.get("SSLEnabled", "false").lower() == "true"
                secure_attr = attrs.get("secure", "false").lower() == "true"
                scheme = attrs.get("scheme", "https" if ssl_enabled_attr else "http")

                entry = {
                    "port": port,
                    "protocol": protocol,
                    "scheme": scheme,
                    "secure": secure_attr or ssl_enabled_attr,
                    "ssl_enabled": ssl_enabled_attr,
                    "address": attrs.get("address"),
                    "redirect_port": attrs.get("redirectPort"),
                    "connection_timeout": attrs.get("connectionTimeout"),
                    "max_threads": attrs.get("maxThreads"),
                    "proxy_name": attrs.get("proxyName"),
                    "proxy_port": attrs.get("proxyPort"),
                    "secret_required": attrs.get("secretRequired"),
                    "secret_configured": "secret" in attrs or "secretRequired" in attrs,
                    "raw_attributes": attrs
                }
                connectors.append(entry)

        return connectors

    # ---------------------------------------------------------
    # REALMS
    # ---------------------------------------------------------

    def get_realms(self, server_xml, context_xml, tomcat_users_xml):
        """
        Collect active Realm configurations across server.xml and context.xml,
        and assess user store presence without recording secrets.
        """
        active_server_xml = self.remove_xml_comments(server_xml)
        active_context_xml = self.remove_xml_comments(context_xml)
        active_users_xml = self.remove_xml_comments(tomcat_users_xml)

        realms = []

        # Find realms in server.xml
        for match in re.finditer(
            r"<Realm\b([^>]*?)(?:>(.*?)</Realm>|/>)",
            active_server_xml,
            flags=re.DOTALL | re.IGNORECASE
        ):
            attrs_str = match.group(1)
            inner_content = match.group(2) or ""
            attrs = self.extract_attributes(attrs_str)
            class_name = attrs.get("className")

            nested_realms = []
            if inner_content:
                for n_match in re.finditer(r"<Realm\b([^>]*)/?>", inner_content, flags=re.IGNORECASE):
                    n_attrs = self.extract_attributes(n_match.group(1))
                    nested_realms.append({
                        "class_name": n_attrs.get("className"),
                        "attributes": n_attrs
                    })

            realms.append({
                "class_name": class_name,
                "context": "server.xml (Catalina Engine/Host)",
                "attributes": attrs,
                "nested_realms": nested_realms
            })

        # Find realms in context.xml
        for match in re.finditer(
            r"<Realm\b([^>]*?)(?:>(.*?)</Realm>|/>)",
            active_context_xml,
            flags=re.DOTALL | re.IGNORECASE
        ):
            attrs = self.extract_attributes(match.group(1))
            realms.append({
                "class_name": attrs.get("className"),
                "context": "context.xml (Context)",
                "attributes": attrs,
                "nested_realms": []
            })

        # Count active users and roles in tomcat-users.xml
        active_users = re.findall(r"<user\b([^>]*)/?>", active_users_xml, flags=re.IGNORECASE)
        active_roles = re.findall(r'<role\b[^>]*\brolename\s*=\s*"([^"]+)"', active_users_xml, flags=re.IGNORECASE)

        lockout_realm_configured = any(
            "LockOutRealm" in (r.get("class_name") or "") for r in realms
        )
        user_database_realm_configured = any(
            "UserDatabaseRealm" in (r.get("class_name") or "") or
            any("UserDatabaseRealm" in (nr.get("class_name") or "") for nr in r.get("nested_realms", []))
            for r in realms
        )

        return {
            "active_realms": realms,
            "realm_count": len(realms),
            "lockout_realm_configured": lockout_realm_configured,
            "user_database_realm_configured": user_database_realm_configured,
            "user_store": {
                "file_path": "/opt/tomcat/conf/tomcat-users.xml",
                "active_user_count": len(active_users),
                "active_role_count": len(active_roles),
                "active_roles": list(set(active_roles)),
                "users_configured": len(active_users) > 0
            }
        }

    # ---------------------------------------------------------
    # DEPLOYED APPLICATIONS INTROSPECTION
    # ---------------------------------------------------------

    def get_deployed_applications_details(self, deployed_apps):
        """
        Inspect each deployed application's web.xml and context.xml.
        """
        app_details = {}

        for app_name in deployed_apps:
            app_dir = f"/opt/tomcat/webapps/{app_name}"
            web_xml_path = f"{app_dir}/WEB-INF/web.xml"
            context_xml_path = f"{app_dir}/META-INF/context.xml"

            web_xml_file = self.get_file(web_xml_path)
            context_xml_file = self.get_file(context_xml_path)

            has_web_xml = bool(web_xml_file["content"].strip())
            has_context_xml = bool(context_xml_file["content"].strip())

            auth_methods = []
            login_config = None
            security_constraints = []
            filters = []
            error_pages = []

            if has_web_xml:
                active_web = self.remove_xml_comments(web_xml_file["content"])

                # Login configuration
                lc_match = re.search(
                    r"<login-config\b[^>]*>(.*?)</login-config>",
                    active_web,
                    flags=re.DOTALL | re.IGNORECASE
                )
                if lc_match:
                    lc_body = lc_match.group(1)
                    am_match = re.search(
                        r"<auth-method>\s*([^<]+?)\s*</auth-method>",
                        lc_body,
                        flags=re.IGNORECASE
                    )
                    rn_match = re.search(
                        r"<realm-name>\s*([^<]+?)\s*</realm-name>",
                        lc_body,
                        flags=re.IGNORECASE
                    )
                    auth_m = am_match.group(1) if am_match else None
                    if auth_m:
                        auth_methods.append(auth_m)
                    login_config = {
                        "auth_method": auth_m,
                        "realm_name": rn_match.group(1) if rn_match else None
                    }

                # Security constraints
                for sc_match in re.finditer(
                    r"<security-constraint\b[^>]*>(.*?)</security-constraint>",
                    active_web,
                    flags=re.DOTALL | re.IGNORECASE
                ):
                    sc_body = sc_match.group(1)

                    resource_collections = []
                    for wrc_match in re.finditer(
                        r"<web-resource-collection\b[^>]*>(.*?)</web-resource-collection>",
                        sc_body,
                        flags=re.DOTALL | re.IGNORECASE
                    ):
                        wrc_body = wrc_match.group(1)
                        wr_name_m = re.search(
                            r"<web-resource-name>\s*([^<]+?)\s*</web-resource-name>",
                            wrc_body,
                            flags=re.IGNORECASE
                        )
                        urls = [
                            u.strip()
                            for u in re.findall(
                                r"<url-pattern>\s*([^<]+?)\s*</url-pattern>",
                                wrc_body,
                                flags=re.IGNORECASE
                            )
                        ]
                        http_methods = [
                            m.strip()
                            for m in re.findall(
                                r"<http-method>\s*([^<]+?)\s*</http-method>",
                                wrc_body,
                                flags=re.IGNORECASE
                            )
                        ]
                        http_omits = [
                            m.strip()
                            for m in re.findall(
                                r"<http-method-omission>\s*([^<]+?)\s*</http-method-omission>",
                                wrc_body,
                                flags=re.IGNORECASE
                            )
                        ]
                        resource_collections.append({
                            "resource_name": wr_name_m.group(1) if wr_name_m else None,
                            "url_patterns": urls,
                            "http_methods": http_methods or ["ALL"],
                            "http_method_omissions": http_omits
                        })

                    auth_constraint = None
                    ac_match = re.search(
                        r"<auth-constraint\b[^>]*>(.*?)</auth-constraint>",
                        sc_body,
                        flags=re.DOTALL | re.IGNORECASE
                    )
                    if ac_match:
                        roles = [
                            r.strip()
                            for r in re.findall(
                                r"<role-name>\s*([^<]+?)\s*</role-name>",
                                ac_match.group(1),
                                flags=re.IGNORECASE
                            )
                        ]
                        auth_constraint = {"roles": roles}

                    tg_match = re.search(
                        r"<transport-guarantee>\s*([^<]+?)\s*</transport-guarantee>",
                        sc_body,
                        flags=re.IGNORECASE
                    )
                    transport_guarantee = tg_match.group(1).strip() if tg_match else "NONE"

                    security_constraints.append({
                        "web_resource_collections": resource_collections,
                        "auth_constraint": auth_constraint,
                        "transport_guarantee": transport_guarantee
                    })

                # Filters
                for f_match in re.finditer(
                    r"<filter\b[^>]*>(.*?)</filter>",
                    active_web,
                    flags=re.DOTALL | re.IGNORECASE
                ):
                    f_body = f_match.group(1)
                    fn_match = re.search(
                        r"<filter-name>\s*([^<]+?)\s*</filter-name>",
                        f_body,
                        flags=re.IGNORECASE
                    )
                    fc_match = re.search(
                        r"<filter-class>\s*([^<]+?)\s*</filter-class>",
                        f_body,
                        flags=re.IGNORECASE
                    )
                    filter_name = fn_match.group(1) if fn_match else ""
                    filter_class = fc_match.group(1) if fc_match else ""

                    init_params = {}
                    for p_match in re.finditer(
                        r"<init-param\b[^>]*>(.*?)</init-param>",
                        f_body,
                        flags=re.DOTALL | re.IGNORECASE
                    ):
                        p_body = p_match.group(1)
                        pn = re.search(
                            r"<param-name>\s*([^<]+?)\s*</param-name>",
                            p_body,
                            flags=re.IGNORECASE
                        )
                        pv = re.search(
                            r"<param-value>\s*([^<]+?)\s*</param-value>",
                            p_body,
                            flags=re.IGNORECASE
                        )
                        if pn and pv:
                            init_params[pn.group(1)] = pv.group(1)

                    filters.append({
                        "filter_name": filter_name,
                        "filter_class": filter_class,
                        "init_params": init_params
                    })

                # Error pages
                for ep_match in re.finditer(
                    r"<error-page\b[^>]*>(.*?)</error-page>",
                    active_web,
                    flags=re.DOTALL | re.IGNORECASE
                ):
                    ep_body = ep_match.group(1)
                    ec_match = re.search(
                        r"<error-code>\s*([^<]+?)\s*</error-code>",
                        ep_body,
                        flags=re.IGNORECASE
                    )
                    loc_match = re.search(
                        r"<location>\s*([^<]+?)\s*</location>",
                        ep_body,
                        flags=re.IGNORECASE
                    )
                    if ec_match or loc_match:
                        error_pages.append({
                            "error_code": ec_match.group(1) if ec_match else None,
                            "location": loc_match.group(1) if loc_match else None
                        })

            # Parse context.xml
            context_attrs = {}
            valves = []
            cookie_processor = None
            if has_context_xml:
                active_ctx = self.remove_xml_comments(context_xml_file["content"])
                ctx_match = re.search(
                    r"<Context\b([^>]*)/?>",
                    active_ctx,
                    flags=re.IGNORECASE
                )
                if ctx_match:
                    context_attrs = self.extract_attributes(ctx_match.group(1))

                for v_match in re.finditer(
                    r"<Valve\b([^>]*)/?>",
                    active_ctx,
                    flags=re.IGNORECASE
                ):
                    v_attrs = self.extract_attributes(v_match.group(1))
                    valves.append(v_attrs)

                cp_match = re.search(
                    r"<CookieProcessor\b([^>]*)/?>",
                    active_ctx,
                    flags=re.IGNORECASE
                )
                if cp_match:
                    cookie_processor = self.extract_attributes(cp_match.group(1))

            app_details[app_name] = {
                "name": app_name,
                "path": app_dir,
                "context_path": "" if app_name == "ROOT" else f"/{app_name}",
                "has_web_xml": has_web_xml,
                "has_context_xml": has_context_xml,
                "auth_methods": auth_methods,
                "login_config": login_config,
                "security_constraints": security_constraints,
                "filters": filters,
                "error_pages": error_pages,
                "context_attributes": context_attrs,
                "context_valves": valves,
                "cookie_processor": cookie_processor
            }

        return app_details

    # ---------------------------------------------------------
    # AUTHENTICATION SUMMARY
    # ---------------------------------------------------------

    def get_authentication_summary(self, global_web_xml, app_details):
        """
        Aggregate authentication mechanisms used across applications.
        """
        active_global_web = self.remove_xml_comments(global_web_xml)

        global_lc_match = re.search(
            r"<login-config\b[^>]*>(.*?)</login-config>",
            active_global_web,
            flags=re.DOTALL | re.IGNORECASE
        )
        global_login_config = None
        if global_lc_match:
            lc_body = global_lc_match.group(1)
            am = re.search(r"<auth-method>\s*([^<]+?)\s*</auth-method>", lc_body, flags=re.IGNORECASE)
            rn = re.search(r"<realm-name>\s*([^<]+?)\s*</realm-name>", lc_body, flags=re.IGNORECASE)
            global_login_config = {
                "auth_method": am.group(1) if am else None,
                "realm_name": rn.group(1) if rn else None
            }

        all_methods = set()
        apps_by_method = {}
        apps_with_auth = []
        apps_without_auth = []

        for app_name, details in app_details.items():
            methods = details.get("auth_methods", [])
            if methods:
                apps_with_auth.append(app_name)
                for m in methods:
                    m_upper = m.upper()
                    all_methods.add(m_upper)
                    apps_by_method.setdefault(m_upper, []).append(app_name)
            else:
                apps_without_auth.append(app_name)

        return {
            "supported_methods": sorted(list(all_methods)),
            "methods_in_use": apps_by_method,
            "apps_with_auth": apps_with_auth,
            "apps_without_auth": apps_without_auth,
            "global_login_config": global_login_config,
            "summary": {
                "digest_configured": "DIGEST" in all_methods,
                "basic_configured": "BASIC" in all_methods,
                "form_configured": "FORM" in all_methods,
                "client_cert_configured": "CLIENT-CERT" in all_methods
            }
        }

    # ---------------------------------------------------------
    # TLS / SSL CONFIGURATION
    # ---------------------------------------------------------

    def get_tls_config(self, connectors, server_xml):
        """
        Inspect TLS/SSL connector parameters and SSLHostConfig without secrets.
        """
        active_xml = self.remove_xml_comments(server_xml)
        tls_connectors = [
            c for c in connectors
            if c.get("ssl_enabled") or c.get("scheme") == "https"
        ]

        ssl_host_configs = []
        for shc_match in re.finditer(
            r"<SSLHostConfig\b([^>]*?)>(.*?)</SSLHostConfig>",
            active_xml,
            flags=re.DOTALL | re.IGNORECASE
        ):
            shc_attrs = self.extract_attributes(shc_match.group(1))
            shc_body = shc_match.group(2)

            certificates = []
            for cert_match in re.finditer(r"<Certificate\b([^>]*)/?>", shc_body, flags=re.IGNORECASE):
                cert_attrs = self.extract_attributes(cert_match.group(1))
                certificates.append({
                    "type": cert_attrs.get("type", "RSA"),
                    "certificate_file": cert_attrs.get("certificateFile"),
                    "certificate_key_file": cert_attrs.get("certificateKeyFile"),
                    "certificate_chain_file": cert_attrs.get("certificateChainFile"),
                    "certificate_keystore_file": cert_attrs.get("certificateKeystoreFile"),
                    "certificate_keystore_type": cert_attrs.get("certificateKeystoreType"),
                    "keystore_configured": bool(cert_attrs.get("certificateKeystoreFile")),
                    "secret_configured": (
                        "certificateKeystorePassword" in cert_attrs
                        or "certificateKeyPassword" in cert_attrs
                    )
                })

            ssl_host_configs.append({
                "host_name": shc_attrs.get("hostName", "_default_"),
                "protocols": shc_attrs.get("protocols"),
                "ciphers": shc_attrs.get("ciphers"),
                "client_auth": shc_attrs.get("certificateVerification", shc_attrs.get("clientAuth", "none")),
                "certificates": certificates
            })

        tls_enabled = len(tls_connectors) > 0 or len(ssl_host_configs) > 0

        return {
            "tls_enabled": tls_enabled,
            "tls_connectors": tls_connectors,
            "ssl_host_configs": ssl_host_configs,
            "jsse_style_configured": any(
                bool(c.get("certificate_keystore_file"))
                for shc in ssl_host_configs
                for c in shc.get("certificates", [])
            ),
            "openssl_style_configured": any(
                bool(c.get("certificate_file"))
                for shc in ssl_host_configs
                for c in shc.get("certificates", [])
            )
        }

    # ---------------------------------------------------------
    # SECURITY CONSTRAINTS AGGREGATION
    # ---------------------------------------------------------

    def get_security_constraints(self, app_details):
        """
        Aggregate all security constraints defined across applications.
        """
        aggregated = []
        for app_name, details in app_details.items():
            for sc in details.get("security_constraints", []):
                for rc in sc.get("web_resource_collections", []):
                    aggregated.append({
                        "application": app_name,
                        "resource_name": rc.get("resource_name"),
                        "url_patterns": rc.get("url_patterns", []),
                        "http_methods": rc.get("http_methods", []),
                        "http_method_omissions": rc.get("http_method_omissions", []),
                        "roles": (
                            sc.get("auth_constraint", {}).get("roles", [])
                            if sc.get("auth_constraint")
                            else []
                        ),
                        "auth_constraint_present": sc.get("auth_constraint") is not None,
                        "transport_guarantee": sc.get("transport_guarantee", "NONE")
                    })

        return aggregated

    # ---------------------------------------------------------
    # MANAGEMENT / ADMIN APPLICATIONS
    # ---------------------------------------------------------

    def get_management_applications(self, deployed_apps, app_details):
        """
        Identify management applications and their security controls.
        """
        known_admin_apps = ["manager", "host-manager"]
        admin_apps = {}

        for name in known_admin_apps:
            is_deployed = name in deployed_apps
            info = {
                "name": name,
                "deployed": is_deployed,
                "path": f"/opt/tomcat/webapps/{name}" if is_deployed else None,
                "context_path": f"/{name}" if is_deployed else None,
                "auth_configured": False,
                "auth_methods": [],
                "security_constraints_count": 0,
                "remote_addr_valve": None,
                "csrf_filter_configured": False,
                "header_security_filter_configured": False
            }

            if is_deployed and name in app_details:
                d = app_details[name]
                info["auth_configured"] = len(d.get("auth_methods", [])) > 0
                info["auth_methods"] = d.get("auth_methods", [])
                info["security_constraints_count"] = len(d.get("security_constraints", []))

                for valve in d.get("context_valves", []):
                    if "RemoteAddrValve" in valve.get("className", ""):
                        info["remote_addr_valve"] = {
                            "className": valve.get("className"),
                            "allow": valve.get("allow")
                        }

                for f in d.get("filters", []):
                    fc = f.get("filter_class", "")
                    if "CsrfPreventionFilter" in fc:
                        info["csrf_filter_configured"] = True
                    if "HttpHeaderSecurityFilter" in fc:
                        info["header_security_filter_configured"] = True

            admin_apps[name] = info

        return admin_apps

    # ---------------------------------------------------------
    # AJP CONFIGURATION
    # ---------------------------------------------------------

    def get_ajp_config(self, connectors):
        """
        Identify active AJP connectors and their security posture.
        """
        ajp_connectors = []
        for c in connectors:
            proto = (c.get("protocol") or "").upper()
            if "AJP" in proto:
                raw = c.get("raw_attributes", {})
                secret_req = raw.get("secretRequired")
                if secret_req is not None:
                    secret_required_val = secret_req.lower() == "true"
                    secret_required_source = "explicit configuration"
                else:
                    # Default in Tomcat 8.5.51+ and 9.0.31+ is true
                    secret_required_val = True
                    secret_required_source = "Tomcat default"

                ajp_connectors.append({
                    "port": c.get("port"),
                    "protocol": c.get("protocol"),
                    "address": c.get("address"),
                    "redirect_port": c.get("redirect_port"),
                    "secret_required": secret_required_val,
                    "secret_required_source": secret_required_source,
                    "secret_configured": c.get("secret_configured", False)
                })

        return {
            "ajp_enabled": len(ajp_connectors) > 0,
            "connectors": ajp_connectors,
            "count": len(ajp_connectors)
        }

    # ---------------------------------------------------------
    # HTTP / PROXY CONFIGURATION
    # ---------------------------------------------------------

    def get_http_proxy_config(self, connectors, server_xml, context_xml):
        """
        Collect HTTP proxying, forwarding headers, and reverse proxy settings.
        """
        active_server_xml = self.remove_xml_comments(server_xml)
        active_context_xml = self.remove_xml_comments(context_xml)

        proxy_connectors = []
        for c in connectors:
            if c.get("proxy_name") or c.get("proxy_port"):
                proxy_connectors.append({
                    "port": c.get("port"),
                    "proxy_name": c.get("proxy_name"),
                    "proxy_port": c.get("proxy_port"),
                    "scheme": c.get("scheme"),
                    "secure": c.get("secure")
                })

        remote_ip_valve = None
        for xml_src, src_label in [(active_server_xml, "server.xml"), (active_context_xml, "context.xml")]:
            m = re.search(
                r'<Valve\b[^>]*className\s*=\s*"org\.apache\.catalina\.valves\.RemoteIpValve"([^>]*)/?>',
                xml_src,
                flags=re.IGNORECASE
            )
            if m:
                attrs = self.extract_attributes(m.group(1))
                remote_ip_valve = {
                    "configured": True,
                    "location": src_label,
                    "remote_ip_header": attrs.get("remoteIpHeader", "x-forwarded-for"),
                    "protocol_header": attrs.get("protocolHeader", "x-forwarded-proto"),
                    "internal_proxies": attrs.get("internalProxies"),
                    "trusted_proxies": attrs.get("trustedProxies")
                }
                break

        if not remote_ip_valve:
            remote_ip_valve = {
                "configured": False,
                "location": None
            }

        return {
            "proxy_connectors": proxy_connectors,
            "proxy_configured": len(proxy_connectors) > 0 or remote_ip_valve["configured"],
            "remote_ip_valve": remote_ip_valve
        }

    # ---------------------------------------------------------
    # FILESYSTEM / DEPLOYMENT CONFIGURATION
    # ---------------------------------------------------------

    def get_deployment_config(self, server_xml):
        """
        Collect deployment flags and host directory permissions.
        """
        active_server_xml = self.remove_xml_comments(server_xml)

        host_match = re.search(r"<Host\b([^>]*)/?>", active_server_xml, flags=re.IGNORECASE)
        host_attrs = self.extract_attributes(host_match.group(1)) if host_match else {}

        app_base = host_attrs.get("appBase", "webapps")
        app_base_source = "explicit configuration" if "appBase" in host_attrs else "Tomcat default"

        auto_deploy_val = host_attrs.get("autoDeploy")
        if auto_deploy_val is not None:
            auto_deploy = auto_deploy_val.lower() == "true"
            auto_deploy_source = "explicit configuration"
        else:
            auto_deploy = True
            auto_deploy_source = "Tomcat default"

        deploy_on_startup_val = host_attrs.get("deployOnStartup")
        if deploy_on_startup_val is not None:
            deploy_on_startup = deploy_on_startup_val.lower() == "true"
            deploy_on_startup_source = "explicit configuration"
        else:
            deploy_on_startup = True
            deploy_on_startup_source = "Tomcat default"

        unpack_wars_val = host_attrs.get("unpackWARs")
        if unpack_wars_val is not None:
            unpack_wars = unpack_wars_val.lower() == "true"
            unpack_wars_source = "explicit configuration"
        else:
            unpack_wars = True
            unpack_wars_source = "Tomcat default"

        # Check for deployed WAR files
        war_output = self.docker_exec(
            "find /opt/tomcat/webapps -maxdepth 1 -type f -name '*.war' -printf '%f\\n' 2>/dev/null"
        )
        war_files = [w.strip() for w in war_output.splitlines() if w.strip()]

        # Safe directory permissions check
        perm_output = self.docker_exec(
            "ls -ld /opt/tomcat/webapps /opt/tomcat/conf /opt/tomcat/temp /opt/tomcat/work /opt/tomcat/logs 2>/dev/null"
        )
        directory_permissions = {}
        for line in perm_output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 9:
                mode = parts[0]
                owner = parts[2]
                group = parts[3]
                path = parts[-1]
                directory_permissions[path] = {
                    "permissions": mode,
                    "owner": owner,
                    "group": group
                }

        return {
            "app_base": app_base,
            "app_base_source": app_base_source,
            "auto_deploy": auto_deploy,
            "auto_deploy_source": auto_deploy_source,
            "deploy_on_startup": deploy_on_startup,
            "deploy_on_startup_source": deploy_on_startup_source,
            "unpack_wars": unpack_wars,
            "unpack_wars_source": unpack_wars_source,
            "deployed_war_files": war_files,
            "directory_permissions": directory_permissions
        }

    # ---------------------------------------------------------
    # OTHER SECURITY CONFIGURATION
    # ---------------------------------------------------------

    def get_other_security_config(self, server_xml, global_web_xml, context_xml, app_details):
        """
        Inspect listeners, valves, shutdown ports, and security filters.
        """
        active_server_xml = self.remove_xml_comments(server_xml)
        active_global_web = self.remove_xml_comments(global_web_xml)
        active_context_xml = self.remove_xml_comments(context_xml)

        server_match = re.search(r"<Server\b([^>]*)/?>", active_server_xml, flags=re.IGNORECASE)
        server_attrs = self.extract_attributes(server_match.group(1)) if server_match else {}
        server_shutdown = {
            "port": server_attrs.get("port", "8005"),
            "shutdown_command_configured": "shutdown" in server_attrs
        }

        security_listener_active = bool(re.search(
            r'<Listener\b[^>]*className\s*=\s*"org\.apache\.catalina\.security\.SecurityListener"',
            active_server_xml,
            flags=re.IGNORECASE
        ))

        version_logger_active = bool(re.search(
            r'<Listener\b[^>]*className\s*=\s*"org\.apache\.catalina\.startup\.VersionLoggerListener"',
            active_server_xml,
            flags=re.IGNORECASE
        ))

        access_log_match = re.search(
            r'<Valve\b[^>]*className\s*=\s*"org\.apache\.catalina\.valves\.AccessLogValve"([^>]*)/?>',
            active_server_xml,
            flags=re.IGNORECASE
        )
        access_log_valve = {
            "configured": bool(access_log_match)
        }
        if access_log_match:
            alv_attrs = self.extract_attributes(access_log_match.group(1))
            access_log_valve.update({
                "directory": alv_attrs.get("directory", "logs"),
                "prefix": alv_attrs.get("prefix"),
                "suffix": alv_attrs.get("suffix"),
                "pattern": alv_attrs.get("pattern")
            })

        error_report_match = re.search(
            r'<Valve\b[^>]*className\s*=\s*"org\.apache\.catalina\.valves\.ErrorReportValve"([^>]*)/?>',
            active_server_xml,
            flags=re.IGNORECASE
        )
        error_report_valve = {
            "configured": bool(error_report_match)
        }
        if error_report_match:
            erv_attrs = self.extract_attributes(error_report_match.group(1))
            error_report_valve.update({
                "show_report": erv_attrs.get("showReport"),
                "show_server_info": erv_attrs.get("showServerInfo")
            })

        global_filters = []
        for f_match in re.finditer(
            r"<filter\b[^>]*>(.*?)</filter>",
            active_global_web,
            flags=re.DOTALL | re.IGNORECASE
        ):
            f_body = f_match.group(1)
            fn = re.search(r"<filter-name>\s*([^<]+?)\s*</filter-name>", f_body, flags=re.IGNORECASE)
            fc = re.search(r"<filter-class>\s*([^<]+?)\s*</filter-class>", f_body, flags=re.IGNORECASE)
            global_filters.append({
                "filter_name": fn.group(1) if fn else "",
                "filter_class": fc.group(1) if fc else ""
            })

        http_header_sec = any("HttpHeaderSecurityFilter" in f.get("filter_class", "") for f in global_filters) or any(
            any("HttpHeaderSecurityFilter" in f.get("filter_class", "") for f in d.get("filters", []))
            for d in app_details.values()
        )

        csrf_sec = any("CsrfPreventionFilter" in f.get("filter_class", "") for f in global_filters) or any(
            any("CsrfPreventionFilter" in f.get("filter_class", "") for f in d.get("filters", []))
            for d in app_details.values()
        )

        cors_sec = any("CorsFilter" in f.get("filter_class", "") for f in global_filters) or any(
            any("CorsFilter" in f.get("filter_class", "") for f in d.get("filters", []))
            for d in app_details.values()
        )

        global_context_match = re.search(r"<Context\b([^>]*)/?>", active_context_xml, flags=re.IGNORECASE)
        global_context_attrs = self.extract_attributes(global_context_match.group(1)) if global_context_match else {}

        allow_linking = global_context_attrs.get("allowLinking", "false").lower() == "true" or any(
            d.get("context_attributes", {}).get("allowLinking", "false").lower() == "true"
            for d in app_details.values()
        )

        privileged_apps = [
            app_name for app_name, d in app_details.items()
            if d.get("context_attributes", {}).get("privileged", "false").lower() == "true"
        ]

        return {
            "server_shutdown": server_shutdown,
            "security_listener": {
                "enabled": security_listener_active,
                "source": "explicit configuration" if security_listener_active else "Tomcat default (disabled)"
            },
            "version_logger_listener": {
                "enabled": version_logger_active
            },
            "access_log_valve": access_log_valve,
            "error_report_valve": error_report_valve,
            "security_filters": {
                "http_header_security_filter_configured": http_header_sec,
                "csrf_prevention_filter_configured": csrf_sec,
                "cors_filter_configured": cors_sec
            },
            "context_security": {
                "allow_linking": allow_linking,
                "privileged_apps": privileged_apps
            }
        }

    # ---------------------------------------------------------
    # GENERIC CONFIGURATION DISCOVERY
    # ---------------------------------------------------------

    STRUCTURED_ELEMENTS = {
        # Server configuration
        "Server": {"port", "shutdown"},
        "Service": {"name"},
        "Executor": {"name", "namePrefix", "maxThreads", "minSpareThreads", "maxIdleTime"},
        "Connector": {
            "port", "protocol", "connectionTimeout", "redirectPort", "maxParameterCount",
            "executor", "SSLEnabled", "secure", "scheme", "address", "maxThreads",
            "proxyName", "proxyPort", "secretRequired", "secret"
        },
        "SSLHostConfig": {
            "hostName", "protocols", "ciphers", "certificateVerification", "clientAuth",
            "truststoreFile", "truststorePassword", "truststoreType", "sslImplementationName"
        },
        "Certificate": {
            "type", "certificateFile", "certificateKeyFile", "certificateChainFile",
            "certificateKeystoreFile", "certificateKeystoreType", "certificateKeystorePassword",
            "certificateKeyPassword"
        },
        "UpgradeProtocol": {"className"},
        "Engine": {"name", "defaultHost", "jvmRoute"},
        "Cluster": {"className"},
        "Host": {
            "name", "appBase", "unpackWARs", "autoDeploy", "deployOnStartup",
            "deployIgnore", "xmlValidation", "xmlNamespaceAware"
        },
        "Context": {
            "path", "docBase", "antiResourceLocking", "privileged", "allowLinking",
            "reloadable", "crossContext", "swallowOutput"
        },
        "Valve": {
            "className", "directory", "prefix", "suffix", "pattern", "allow", "deny",
            "remoteIpHeader", "protocolHeader", "internalProxies", "trustedProxies",
            "showReport", "showServerInfo"
        },
        "Realm": {
            "className", "resourceName", "appName", "userDatabase", "digest",
            "allRolesMode", "localDataSource", "userTable", "roleNameCol",
            "userNameCol", "userCredCol", "userRoleTable"
        },
        "Listener": {"className"},
        "GlobalNamingResources": set(),
        "Resource": {"name", "auth", "type", "description", "factory", "pathname"},
        "CookieProcessor": {"className", "sameSiteCookies"},
        "Manager": {
            "className", "pathname", "maxActiveSessions",
            "sessionAttributeValueClassNameFilter"
        },
        "Store": {"className"},
        "WatchedResource": set(),

        # Web application deployment descriptor elements (web.xml)
        "web-app": {"version", "metadata-complete", "id"},
        "display-name": {"id"},
        "description": {"id"},
        "request-character-encoding": set(),
        "response-character-encoding": set(),
        "context-param": {"id"},
        "param-name": {"id"},
        "param-value": {"id"},
        "servlet": {"id"},
        "servlet-name": {"id"},
        "servlet-class": {"id"},
        "jsp-file": {"id"},
        "load-on-startup": {"id"},
        "init-param": {"id"},
        "multipart-config": set(),
        "max-file-size": set(),
        "max-request-size": set(),
        "file-size-threshold": set(),
        "servlet-mapping": {"id"},
        "url-pattern": {"id"},
        "filter": {"id"},
        "filter-name": {"id"},
        "filter-class": {"id"},
        "async-supported": set(),
        "filter-mapping": {"id"},
        "dispatcher": set(),
        "listener": {"id"},
        "listener-class": {"id"},
        "security-constraint": {"id"},
        "web-resource-collection": {"id"},
        "web-resource-name": {"id"},
        "http-method": set(),
        "http-method-omission": set(),
        "auth-constraint": {"id"},
        "role-name": {"id"},
        "user-data-constraint": {"id"},
        "transport-guarantee": set(),
        "login-config": {"id"},
        "auth-method": set(),
        "realm-name": set(),
        "form-login-config": set(),
        "form-login-page": set(),
        "form-error-page": set(),
        "security-role": {"id"},
        "error-page": {"id"},
        "error-code": set(),
        "exception-type": set(),
        "location": set(),
        "session-config": {"id"},
        "session-timeout": set(),
        "cookie-config": set(),
        "tracking-mode": set(),
        "mime-mapping": set(),
        "extension": set(),
        "mime-type": set(),
        "welcome-file-list": set(),
        "welcome-file": set(),
        "jsp-config": set(),
        "taglib": set(),
        "taglib-uri": set(),
        "taglib-location": set(),
        "env-entry": set(),
        "resource-ref": set(),
        "resource-env-ref": set(),

        # tomcat-users.xml
        "tomcat-users": {"version"},
        "user": {"username", "password", "roles", "groups"},
        "role": {"rolename"},
        "group": {"groupname", "roles"}
    }

    IGNORED_ATTRS = {
        "xmlns", "schemalocation", "no_namespace_schema_location", "id", "version"
    }

    @staticmethod
    def _strip_ns(tag):
        if not tag:
            return ""
        return tag.split("}", 1)[1] if "}" in tag else tag

    @staticmethod
    def _sanitize_val(val, key=""):
        if not val:
            return val
        key_lower = key.lower()
        if any(s in key_lower for s in ["password", "secret", "keypass", "storepass", "privatekey", "token"]):
            return "[REDACTED]"
        return val

    def _build_element_dict(self, elem):
        raw_tag = self._strip_ns(elem.tag)
        attrs = {
            self._strip_ns(k): self._sanitize_val(v, self._strip_ns(k))
            for k, v in elem.attrib.items()
            if not self._strip_ns(k).lower().startswith("xmlns")
            and self._strip_ns(k).lower() not in self.IGNORED_ATTRS
        }
        text = elem.text.strip() if elem.text and elem.text.strip() else None
        children = [self._build_element_dict(child) for child in elem]
        return {
            "element": raw_tag,
            "attributes": attrs,
            "text": text,
            "children": children
        }

    def _scan_xml_element(self, elem, file_path, app_name, unknown_elements, unknown_attributes):
        raw_tag = self._strip_ns(elem.tag)

        if raw_tag not in self.STRUCTURED_ELEMENTS:
            # Unknown element discovered: capture element, attributes, text, and nested hierarchy
            entry = {
                "element": raw_tag,
                "source_file": file_path,
                "application": app_name,
                "attributes": {
                    self._strip_ns(k): self._sanitize_val(v, self._strip_ns(k))
                    for k, v in elem.attrib.items()
                    if not self._strip_ns(k).lower().startswith("xmlns")
                    and self._strip_ns(k).lower() not in self.IGNORED_ATTRS
                },
                "text": elem.text.strip() if elem.text and elem.text.strip() else None,
                "children": [self._build_element_dict(child) for child in elem]
            }
            unknown_elements.append(entry)
            return 1 + sum(len(list(e.iter())) - 1 for e in [elem])

        eval_count = 1
        known_attrs = self.STRUCTURED_ELEMENTS[raw_tag]
        for k, v in elem.attrib.items():
            clean_k = self._strip_ns(k)
            clean_k_lower = clean_k.lower()
            if clean_k_lower.startswith("xmlns") or clean_k_lower in self.IGNORED_ATTRS:
                continue
            if clean_k not in known_attrs:
                unknown_attributes.append({
                    "element": raw_tag,
                    "attribute": clean_k,
                    "value": self._sanitize_val(v, clean_k),
                    "source_file": file_path,
                    "application": app_name
                })

        for child in elem:
            eval_count += self._scan_xml_element(child, file_path, app_name, unknown_elements, unknown_attributes)

        return eval_count

    def discover_configuration(self, tomcat_version=None, deployed_apps=None):
        """
        Generic configuration discovery layer:
        Inspects active XML across Tomcat server and web application descriptors
        to detect unrepresented/unknown elements and attributes without assigning
        security meanings or assuming fixed future schemas.
        """
        if tomcat_version is None:
            v_info = self.get_tomcat_version()
            tomcat_version = v_info.get("version")

        if deployed_apps is None:
            deployed_apps = self.get_deployed_apps()

        sources = [
            ("/opt/tomcat/conf/server.xml", None),
            ("/opt/tomcat/conf/web.xml", None),
            ("/opt/tomcat/conf/context.xml", None),
            ("/opt/tomcat/conf/tomcat-users.xml", None),
        ]

        for app in deployed_apps:
            sources.append((f"/opt/tomcat/webapps/{app}/WEB-INF/web.xml", app))
            sources.append((f"/opt/tomcat/webapps/{app}/META-INF/context.xml", app))

        unknown_elements = []
        unknown_attributes = []
        sources_scanned = []
        total_elements_evaluated = 0

        for file_path, app_name in sources:
            file_data = self.get_file(file_path)
            content = file_data.get("content", "")
            active_xml = self.remove_xml_comments(content)

            if not active_xml.strip():
                continue

            sources_scanned.append(file_path)

            try:
                root = ET.fromstring(active_xml)
                eval_count = self._scan_xml_element(
                    root,
                    file_path,
                    app_name,
                    unknown_elements,
                    unknown_attributes
                )
                total_elements_evaluated += eval_count
            except Exception:
                # Graceful fallback on malformed XML
                for match in re.finditer(r"<([a-zA-Z0-9_\.:-]+)\b([^>]*)/?>", active_xml):
                    tag = self._strip_ns(match.group(1))
                    attrs = self.extract_attributes(match.group(2))
                    total_elements_evaluated += 1

                    if tag not in self.STRUCTURED_ELEMENTS:
                        unknown_elements.append({
                            "element": tag,
                            "source_file": file_path,
                            "application": app_name,
                            "attributes": attrs,
                            "text": None,
                            "children": []
                        })
                    else:
                        known_attrs = self.STRUCTURED_ELEMENTS[tag]
                        for ak, av in attrs.items():
                            if ak not in known_attrs and ak.lower() not in self.IGNORED_ATTRS:
                                unknown_attributes.append({
                                    "element": tag,
                                    "attribute": ak,
                                    "value": self._sanitize_val(av, ak),
                                    "source_file": file_path,
                                    "application": app_name
                                })

        return {
            "tomcat_version": tomcat_version,
            "unknown_elements": unknown_elements,
            "unknown_attributes": unknown_attributes,
            "sources_scanned": sources_scanned,
            "discovery_summary": {
                "sources_scanned_count": len(sources_scanned),
                "unknown_elements_count": len(unknown_elements),
                "unknown_attributes_count": len(unknown_attributes),
                "active_elements_evaluated": total_elements_evaluated
            }
        }

    # ---------------------------------------------------------
    # EFFECTIVE CONFIGURATION
    # ---------------------------------------------------------

    def build_effective_configuration(
        self,
        web_xml,
        context_xml,
        server_xml,
        tomcat_users_xml=None,
        tomcat_version=None
    ):
        """
        Assemble the comprehensive, generic effective configuration dictionary.
        All 5 legacy keys are preserved with backward-compatible types.
        """
        if web_xml is None:
            web_xml = ""
        if context_xml is None:
            context_xml = ""
        if server_xml is None:
            server_xml = ""
        if tomcat_users_xml is None:
            users_file = self.get_file("/opt/tomcat/conf/tomcat-users.xml")
            tomcat_users_xml = users_file.get("content", "")

        # Preserved core components
        default_servlet = self.get_default_servlet_effective_config(web_xml)
        session_persistence = self.get_session_persistence(context_xml)
        connectors = self.get_connectors(server_xml)
        application_jars = self.get_application_jars()
        deployed_apps = self.get_deployed_apps()

        # Detailed environmental introspection
        jar_details = self.parse_jar_details(application_jars)
        server_jars = self.get_server_jars()
        app_details = self.get_deployed_applications_details(deployed_apps)

        # Generic structured security sections
        realms = self.get_realms(server_xml, context_xml, tomcat_users_xml)
        authentication = self.get_authentication_summary(web_xml, app_details)
        tls = self.get_tls_config(connectors, server_xml)
        security_constraints = self.get_security_constraints(app_details)
        management_apps = self.get_management_applications(deployed_apps, app_details)
        ajp = self.get_ajp_config(connectors)
        http_proxy = self.get_http_proxy_config(connectors, server_xml, context_xml)
        deployment = self.get_deployment_config(server_xml)
        other_sec = self.get_other_security_config(server_xml, web_xml, context_xml, app_details)

        # Generic configuration discovery layer
        configuration_discovery = self.discover_configuration(
            tomcat_version=tomcat_version,
            deployed_apps=deployed_apps
        )

        return {
            # --- 5 PRESERVED KEYS (Exact same structure & types) ---
            "default_servlet": default_servlet,
            "session_persistence": session_persistence,
            "application_libraries": {
                "jar_files": application_jars,
                "count": len(application_jars),
                "jar_details": jar_details,
                "server_libraries": server_jars,
                "server_libraries_count": len(server_jars)
            },
            "deployed_applications": deployed_apps,
            "connectors": connectors,

            # --- EXTENDED GENERIC SECTIONS ---
            "authentication": authentication,
            "realms": realms,
            "tls": tls,
            "security_constraints": security_constraints,
            "management_applications": management_apps,
            "ajp": ajp,
            "http_proxy": http_proxy,
            "deployment": deployment,
            "other_security_configuration": other_sec,

            # --- GENERIC CONFIGURATION DISCOVERY ---
            "configuration_discovery": configuration_discovery
        }

    # ---------------------------------------------------------
    # MAIN COLLECTION
    # ---------------------------------------------------------

    def collect(self):
        """
        Collect Tomcat version, raw configurations, and effective configuration.
        """
        version = self.get_tomcat_version()
        web_xml = self.get_file("/opt/tomcat/conf/web.xml")
        context_xml = self.get_file("/opt/tomcat/conf/context.xml")
        server_xml = self.get_file("/opt/tomcat/conf/server.xml")
        tomcat_users_xml = self.get_file("/opt/tomcat/conf/tomcat-users.xml")

        effective_configuration = self.build_effective_configuration(
            web_xml["content"],
            context_xml["content"],
            server_xml["content"],
            tomcat_users_xml["content"],
            tomcat_version=version.get("version")
        )

        return {
            "collector": "tomcat_config_collector",
            "container": self.container_name,
            "tomcat": version,
            "effective_configuration": effective_configuration,
            "configuration_discovery": effective_configuration["configuration_discovery"],
            "raw_configuration": {
                "web_xml": web_xml,
                "context_xml": context_xml,
                "server_xml": server_xml,
                "tomcat_users_xml": tomcat_users_xml
            }
        }


def collect_tomcat_config(container_name):
    """
    Entry point to instantiate collector and execute collection.
    """
    collector = TomcatConfigCollector(container_name)
    return collector.collect()


# ---------------------------------------------------------
# COMMAND LINE
# ---------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Collect effective and raw Tomcat security configuration"
    )

    parser.add_argument(
        "--container",
        required=True,
        help="Docker container name"
    )

    parser.add_argument(
        "--output",
        default="tomcat-config.json",
        help="Output JSON file"
    )

    args = parser.parse_args()

    data = collect_tomcat_config(args.container)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print("Tomcat configuration collected successfully.")
    print(f"Container: {args.container}")
    print(f"Output: {args.output}")
    print()
    print("Effective configuration:")
    print(json.dumps(data["effective_configuration"], indent=2))