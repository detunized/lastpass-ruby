all:
	@# TODO: This is a temporary hack for ST3.
	@#       Figure out why ST3 doesn't use the environment of the launching process.
	@PATH=${HOME}/.rbenv/shims:${PATH} rake spec
