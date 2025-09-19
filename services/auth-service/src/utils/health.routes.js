const success = (res, data, message = 'Success', status = 200) =>
  res.status(status).json({ success: true, message, data });

const failure = (res, message = 'Error', status = 500, errors = null) =>
  res.status(status).json({ success: false, message, errors });

module.exports = { success, failure };