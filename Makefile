# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = PythonSecurity
SOURCEDIR     = .
BUILDDIR      = build

.PHONY: html

doc: html
	make html

venv:
	./venv.sh

vulnerabilities.rst: vulnerabilities.yml venv
	./venv/bin/python render_doc.py

html: vulnerabilities.rst
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

clean:
	rm -rf vulnerabilities.rst build/ venv/
