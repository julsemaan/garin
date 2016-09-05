install-conf:
	sed -e 's/^;*/;/' garin.conf.defaults > /etc/garin.conf
	sed -i -e 's/^;\[/\[/' /etc/garin.conf
