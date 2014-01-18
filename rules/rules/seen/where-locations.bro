@load base/frameworks/intel

export {
        redef enum Intel::Where += {
                HTTP::IN_URL_PATH,
	};

	redef enum Intel::Type += {
		Intel::URL_PATH,
	};
}
