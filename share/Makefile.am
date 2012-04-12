
include $(top_srcdir)/Makefile.am.common

sysconf_DATA = rcsredirect.conf \
				redirect_fqdn.txt \
				redirect_url.txt \
				redirect_user.txt \
				redirect.html \
				intercept_file.txt \
				cat.rules \
				filter.rules

EXTRA_DIST = rcsredirect.conf \
			  	redirect_fqdn.txt \
				redirect_url.txt \
				redirect_user.txt \
				redirect.html \
				intercept_file.txt \
				rcsnia.conf \
				rcsnia.init \
				capture.conf \
				capture.init

install-data-hook:
	install -d $(DESTDIR)/etc/init.d/
	install -m 755 rcsnia.init $(DESTDIR)/etc/init.d/rcsnia
	install -m 755 capture.init $(DESTDIR)/etc/init.d/capture
	install -d $(DESTDIR)/etc/conf.d/
	install -m 644 rcsnia.conf $(DESTDIR)/etc/conf.d/rcsnia
	install -m 644 capture.conf $(DESTDIR)/etc/conf.d/capture

uninstall-hook:
	rm -rf $(DESTDIR)/etc/conf.d/rcsnia
	rm -rf $(DESTDIR)/etc/init.d/rcsnia
	rm -rf $(DESTDIR)/etc/conf.d/capture
	rm -rf $(DESTDIR)/etc/init.d/capture

# vim:ts=4:noexpandtab
