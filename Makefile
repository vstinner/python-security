# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = PythonSecurity
SOURCEDIR     = .
BUILDDIR      = build

.PHONY: html

html: vulnerabilities.rst
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

venv:
	./venv.sh

vulnerabilities.rst: render_doc.py vulnerabilities.yaml venv python_releases.txt
	./venv/bin/python render_doc.py

update: venv
	./venv/bin/python render_doc.py update

clean:
	rm -rf vulnerabilities.rst build/ venv/ vuln/
