@load base/frameworks/intel

export {
        redef enum Intel::Where += {
                HTTP::IN_URL_PATH,
		HTTP::IN_STATUS_CODE,
	};

	redef enum Intel::Type += {
		Intel::URL_PATH,
		Intel::RETURN_CODE,
	};
}
